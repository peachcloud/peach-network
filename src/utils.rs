use regex::Regex;
use snafu::ResultExt;

use crate::error::*;

/// Return matches for a given Regex pattern and text
///
/// # Arguments
///
/// * `pattern` - A string slice containing a regular expression
/// * `text` - A string slice containing the text to be matched on
///
pub fn regex_finder(pattern: &str, text: &str) -> Result<Option<String>, NetworkError> {
    let re = Regex::new(pattern).context(Regex)?;
    let caps = re.captures(text);
    let result = caps.map(|caps| caps[1].to_string());

    Ok(result)
}
