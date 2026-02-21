pub(crate) struct UpPrompt {
    pub title: String,
    pub description: String,
}

pub(crate) fn make_credential_prompt(rp_id: &str, rp_name: Option<&str>, user_display: Option<&str>) -> UpPrompt {
    let site = match rp_name {
        Some(name) => format!("{name} ({rp_id})"),
        None => rp_id.to_string(),
    };
    let account = user_display.unwrap_or("(unknown)");
    UpPrompt {
        title: "fidorium".to_string(),
        description: format!("Register new passkey\n\nSite: {site}\nAccount: {account}\n\nPress OK to create, or Cancel to deny."),
    }
}

pub(crate) fn get_assertion_prompt(rp_id: &str, user_display: Option<&str>) -> UpPrompt {
    let account = user_display.unwrap_or("(unknown)");
    UpPrompt {
        title: "fidorium".to_string(),
        description: format!("Sign in with passkey\n\nSite: {rp_id}\nAccount: {account}\n\nPress OK to sign in, or Cancel to deny."),
    }
}
