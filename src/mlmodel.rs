// Inference for the supervised ML model (LightGBM, exported to JSON).
// Format: see ml/MODEL_FORMAT.md. Tree traversal is iterative and allocation-free
// in the hot path. The model is loaded from a file and kept behind an ArcSwapOption
// so it can be hot-swapped without a restart.

use serde::Deserialize;
use std::sync::Arc;

use crate::features;

#[derive(Deserialize)]
struct Node {
    leaf: bool,
    #[serde(default)]
    value: f64,
    #[serde(default)]
    feature: usize,
    #[serde(default)]
    threshold: f64,
    #[serde(default)]
    left: usize,
    #[serde(default)]
    right: usize,
    #[serde(default = "default_true")]
    default_left: bool,
}

fn default_true() -> bool { true }

#[derive(Deserialize)]
struct RawModel {
    feature_version: u32,
    n_features: usize,
    #[serde(default)]
    objective: String,
    trees: Vec<Vec<Node>>,
}

pub struct Model {
    trees: Vec<Vec<Node>>,
    node_mean: Vec<Vec<f64>>, // mean subtree leaf value per node (used for Saabas attribution)
}

/// Mean subtree leaf values per node (post-order, unweighted).
fn subtree_mean(tree: &[Node], idx: usize, means: &mut [f64], depth: u32) -> (f64, u32) {
    if idx >= tree.len() || depth > 128 {
        return (0.0, 0);
    }
    let n = &tree[idx];
    if n.leaf {
        means[idx] = n.value;
        return (n.value, 1);
    }
    let (ls, lc) = subtree_mean(tree, n.left, means, depth + 1);
    let (rs, rc) = subtree_mean(tree, n.right, means, depth + 1);
    let cnt = lc + rc;
    means[idx] = if cnt > 0 { (ls + rs) / cnt as f64 } else { n.value };
    (ls + rs, cnt)
}

fn build_means(trees: &[Vec<Node>]) -> Vec<Vec<f64>> {
    trees.iter().map(|tree| {
        let mut means = vec![0.0f64; tree.len()];
        if !tree.is_empty() {
            let _ = subtree_mean(tree, 0, &mut means, 0);
        }
        means
    }).collect()
}

impl Model {
    fn build(trees: Vec<Vec<Node>>) -> Arc<Model> {
        let node_mean = build_means(&trees);
        Arc::new(Model { trees, node_mean })
    }
    /// Load from a JSON file. Verifies feature-version compatibility.
    pub fn load(path: &str) -> Option<Arc<Model>> {
        let data = std::fs::read_to_string(path).ok()?;
        let raw: RawModel = serde_json::from_str(&data).ok()?;
        if raw.feature_version != features::FEATURE_VERSION {
            tracing::error!(
                "ML model: incompatible feature version {} (node {})",
                raw.feature_version, features::FEATURE_VERSION
            );
            return None;
        }
        if raw.n_features != features::N_FEATURES {
            tracing::error!(
                "ML model: n_features {} != node {}",
                raw.n_features, features::N_FEATURES
            );
            return None;
        }
        tracing::info!(
            "ML model loaded: {} trees, objective={}",
            raw.trees.len(), raw.objective
        );
        Some(Model::build(raw.trees))
    }

    /// Default model EMBEDDED into the binary at compile time (src/default_model.json).
    /// Used when no external model is configured, so ML works right after installation.
    /// An empty tree set (placeholder) is treated as 'no model' and yields None.
    pub fn load_default() -> Option<Arc<Model>> {
        const DEFAULT: &str = include_str!("default_model.json");
        let raw: RawModel = serde_json::from_str(DEFAULT).ok()?;
        if raw.trees.is_empty() {
            return None; // placeholder — no real model has been embedded
        }
        if raw.feature_version != features::FEATURE_VERSION || raw.n_features != features::N_FEATURES {
            tracing::error!(
                "built-in ML model incompatible: fv={} nf={} (node fv={} nf={})",
                raw.feature_version, raw.n_features, features::FEATURE_VERSION, features::N_FEATURES
            );
            return None;
        }
        tracing::info!("built-in ML model: {} trees", raw.trees.len());
        Some(Model::build(raw.trees))
    }

    /// Raw score = the sum of leaf values across all trees.
    fn raw_score(&self, feats: &[f32; features::N_FEATURES]) -> f64 {
        let mut sum = 0.0f64;
        for tree in &self.trees {
            if tree.is_empty() { continue; }
            let mut idx = 0usize;
            loop {
                let node = &tree[idx];
                if node.leaf {
                    sum += node.value;
                    break;
                }
                let v = feats.get(node.feature).copied().unwrap_or(f32::NAN) as f64;
                let go_left = if v.is_nan() {
                    node.default_left
                } else {
                    v <= node.threshold
                };
                idx = if go_left { node.left } else { node.right };
                if idx >= tree.len() { break; } // guards against a malformed tree
            }
        }
        sum
    }

    /// Attack probability in [0..1] (sigmoid of raw_score for binary objectives).
    pub fn predict(&self, feats: &[f32; features::N_FEATURES]) -> f64 {
        let raw = self.raw_score(feats);
        1.0 / (1.0 + (-raw).exp())
    }

    /// Feature attribution along decision paths (Saabas method): a feature's contribution at a split is
    /// (mean of the chosen child − mean of the current node), summed over all trees.
    /// Returns the vector of contributions to raw_score (sum + bias = raw_score).
    pub fn contrib(&self, feats: &[f32; features::N_FEATURES]) -> [f64; features::N_FEATURES] {
        let mut contrib = [0.0f64; features::N_FEATURES];
        for (t, tree) in self.trees.iter().enumerate() {
            if tree.is_empty() { continue; }
            let means = &self.node_mean[t];
            let mut idx = 0usize;
            let mut depth = 0u32;
            loop {
                let node = &tree[idx];
                if node.leaf { break; }
                let cur = means.get(idx).copied().unwrap_or(0.0);
                let v = feats.get(node.feature).copied().unwrap_or(f32::NAN) as f64;
                let go_left = if v.is_nan() { node.default_left } else { v <= node.threshold };
                let child = if go_left { node.left } else { node.right };
                let child_mean = means.get(child).copied().unwrap_or(cur);
                if node.feature < features::N_FEATURES {
                    contrib[node.feature] += child_mean - cur;
                }
                idx = child;
                depth += 1;
                if idx >= tree.len() || depth > 128 { break; }
            }
        }
        contrib
    }

    /// Top-K feature names pushing the score UP (toward attack). Positive contributions only.
    /// Used by the event view to answer 'why was this blocked'.
    pub fn top_features(&self, feats: &[f32; features::N_FEATURES], k: usize) -> Vec<&'static str> {
        let contrib = self.contrib(feats);
        let mut idx: Vec<usize> = (0..features::N_FEATURES).collect();
        idx.sort_by(|&a, &b| contrib[b].partial_cmp(&contrib[a]).unwrap_or(std::cmp::Ordering::Equal));
        idx.into_iter()
            .filter(|&i| contrib[i] > 0.0)
            .take(k)
            .map(|i| features::FEATURE_NAMES[i])
            .collect()
    }
}
