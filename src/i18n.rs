//! Localisation of the default pages (block, challenge, error) to the visitor's language.
//! Language selection: Accept-Language when supported, then the geo country, then en.
//! The supported page languages match those of the dashboard: en, ru, zh, pt.

fn supported(code: &str) -> Option<&'static str> {
    match code {
        "en" => Some("en"),
        "ru" => Some("ru"),
        "zh" => Some("zh"),
        "pt" => Some("pt"),
        _ => None,
    }
}

/// Language index into the tables: en=0, ru=1, zh=2, pt=3.
fn idx(lang: &str) -> usize {
    match lang {
        "ru" => 1,
        "zh" => 2,
        "pt" => 3,
        _ => 0,
    }
}

/// Page language: Accept-Language first, then country (ISO-3166 alpha-2), then en.
pub fn page_lang(country: &str, accept_language: Option<&str>) -> &'static str {
    // 1) Accept-Language: the first supported tag ("ru", "zh-CN", "pt-BR;q=0.9")
    if let Some(al) = accept_language {
        for part in al.split(',') {
            let tag = part.split(';').next().unwrap_or("").trim();
            let primary = tag.split('-').next().unwrap_or("").to_ascii_lowercase();
            if let Some(l) = supported(&primary) {
                return l;
            }
        }
    }
    // 2) country -> language
    match country.to_ascii_uppercase().as_str() {
        "RU" | "BY" | "KZ" | "KG" => "ru",
        "CN" | "HK" | "TW" | "MO" | "SG" => "zh",
        "PT" | "BR" | "AO" | "MZ" => "pt",
        _ => "en",
    }
}

/// Localised reason for an HTTP status. [en, ru, zh, pt].
pub fn block_reason(status: u16, lang: &str) -> &'static str {
    let row: usize = match status {
        400 => 0, 401 => 1, 403 => 2, 404 => 3, 405 => 4, 406 => 5,
        429 => 6, 451 => 7, 500 => 8, 502 => 9, 503 => 10, 504 => 11, _ => 12,
    };
    const R: [[&str; 4]; 13] = [
        ["Bad request", "Неверный запрос", "错误请求", "Requisição inválida"],
        ["Authentication required", "Требуется авторизация", "需要身份验证", "Autenticação necessária"],
        ["Access denied", "Доступ запрещён", "访问被拒绝", "Acesso negado"],
        ["Not found", "Не найдено", "未找到", "Não encontrado"],
        ["Method not allowed", "Метод не разрешён", "方法不被允许", "Método não permitido"],
        ["Request rejected", "Запрос отклонён", "请求被拒绝", "Requisição rejeitada"],
        ["Too many requests", "Слишком много запросов", "请求过多", "Muitas requisições"],
        ["Unavailable for legal reasons", "Недоступно по юридическим причинам", "因法律原因不可用", "Indisponível por motivos legais"],
        ["Internal error", "Внутренняя ошибка", "内部错误", "Erro interno"],
        ["Gateway error", "Ошибка шлюза", "网关错误", "Erro de gateway"],
        ["Service unavailable", "Сервис недоступен", "服务不可用", "Serviço indisponível"],
        ["Gateway timeout", "Шлюз не отвечает", "网关超时", "Tempo limite do gateway"],
        ["Request blocked", "Запрос заблокирован", "请求被拦截", "Requisição bloqueada"],
    ];
    R[row][idx(lang)]
}

/// Description text shown on the block page.
pub fn block_desc(lang: &str) -> &'static str {
    const T: [&str; 4] = [
        "Your request was blocked by the site's protection system. If you believe this is a mistake, share the incident code below with the administrator.",
        "Ваш запрос был заблокирован системой защиты сайта. Если вы считаете, что это произошло по ошибке, передайте администратору код инцидента ниже.",
        "您的请求已被本站的防护系统拦截。如果您认为这是误判，请将下方的事件代码提供给管理员。",
        "Sua requisição foi bloqueada pelo sistema de proteção do site. Se você acredita que isto é um engano, informe ao administrador o código do incidente abaixo.",
    ];
    T[idx(lang)]
}

/// Label for the incident code field.
pub fn incident_label(lang: &str) -> &'static str {
    const T: [&str; 4] = ["Incident code", "Код инцидента", "事件代码", "Código do incidente"];
    T[idx(lang)]
}

/// Infrastructure error description by code (for error_page). [en, ru, zh, pt].
pub fn error_desc(status: u16, lang: &str) -> &'static str {
    let row: usize = match status {
        400 => 0, 404 => 1, 413 => 2, 414 => 3, 429 => 4, 500 => 5, 502 => 6, 503 => 7, 504 => 8, _ => 9,
    };
    const D: [[&str; 4]; 10] = [
        ["The server could not process the request due to invalid syntax.", "Сервер не смог обработать запрос из-за неверного синтаксиса.", "服务器因语法无效无法处理该请求。", "O servidor não pôde processar a requisição devido a sintaxe inválida."],
        ["The requested site is not served on this server.", "Запрошенный сайт не обслуживается на этом сервере.", "此服务器不提供所请求的站点。", "O site solicitado não é atendido neste servidor."],
        ["The request body is too large and was rejected.", "Тело запроса слишком большое и было отклонено.", "请求体过大，已被拒绝。", "O corpo da requisição é grande demais e foi rejeitado."],
        ["The request URL is too long.", "Адрес запроса слишком длинный.", "请求地址过长。", "O endereço da requisição é muito longo."],
        ["Too many requests in a short time. Please try again later.", "Слишком много запросов за короткое время. Повторите попытку позже.", "短时间内请求过多。请稍后再试。", "Muitas requisições em pouco tempo. Tente novamente mais tarde."],
        ["An internal server error occurred.", "На сервере произошла внутренняя ошибка.", "服务器发生内部错误。", "Ocorreu um erro interno no servidor."],
        ["The origin server is unavailable or returned an invalid response. Try refreshing in a few seconds.", "Сервер-источник недоступен или вернул некорректный ответ. Попробуйте обновить страницу через несколько секунд.", "源服务器不可用或返回了无效响应。请几秒后刷新。", "O servidor de origem está indisponível ou retornou uma resposta inválida. Tente atualizar em alguns segundos."],
        ["The service is temporarily unavailable. Maintenance or overload.", "Сервис временно недоступен. Идут технические работы или перегрузка.", "服务暂时不可用。正在维护或过载。", "O serviço está temporariamente indisponível. Manutenção ou sobrecarga."],
        ["The origin server did not respond in time.", "Сервер-источник не ответил вовремя.", "源服务器未及时响应。", "O servidor de origem não respondeu a tempo."],
        ["The request cannot be processed.", "Запрос не может быть обработан.", "无法处理该请求。", "A requisição não pode ser processada."],
    ];
    D[row][idx(lang)]
}

/// Strings for the browser challenge page.
pub fn chl_title(lang: &str) -> &'static str {
    const T: [&str; 4] = ["Checking your browser", "Проверка браузера", "正在检查您的浏览器", "Verificando seu navegador"];
    T[idx(lang)]
}
pub fn chl_heading(lang: &str) -> &'static str {
    const T: [&str; 4] = ["Checking your browser…", "Проверяем ваш браузер…", "正在检查您的浏览器…", "Verificando seu navegador…"];
    T[idx(lang)]
}
pub fn chl_message(lang: &str) -> &'static str {
    const T: [&str; 4] = [
        "This will take a few seconds. Please wait — the check runs automatically.",
        "Это займёт несколько секунд. Пожалуйста, подождите — проверка выполняется автоматически.",
        "这将需要几秒钟。请稍候——验证会自动完成。",
        "Isto levará alguns segundos. Aguarde — a verificação é automática.",
    ];
    T[idx(lang)]
}
pub fn chl_footer(lang: &str) -> &'static str {
    const T: [&str; 4] = [
        "Protection against automated traffic",
        "Защита от автоматизированного трафика",
        "防止自动化流量的保护",
        "Proteção contra tráfego automatizado",
    ];
    T[idx(lang)]
}
