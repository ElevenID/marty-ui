//! Pure renderer: read nonsecret profile bindings from stdin; never seed a DB.
use marty_canvas_demo_seed::{native_badge_templates, NativeBadgeTemplateInput};
use std::io::{self, Read};

fn main() {
    let result = (|| -> Result<(), String> {
        let mut bytes = String::new();
        io::stdin()
            .take(65537)
            .read_to_string(&mut bytes)
            .map_err(|_| "Cannot read template bindings")?;
        if bytes.len() > 65536 {
            return Err("Template bindings exceed input limit".into());
        }
        let input: NativeBadgeTemplateInput =
            serde_json::from_str(&bytes).map_err(|_| "Invalid native template bindings")?;
        println!("{}", native_badge_templates(&input)?);
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
