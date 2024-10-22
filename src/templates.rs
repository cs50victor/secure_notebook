pub const ALL_ACCESS: &str = "
(version 1)
; Allow everything by default
(allow default)
";

pub const NO_ACCESS: &str = "
(version 1)
; Allow everything by default
(allow default)
";

// pub const NO_FILE_ACCESS: &str = "
// sandbox-exec -p '(version 1)

// ; Allow everything by default
// (allow default)

// ; Deny file read and write permissions to /Users/vic8or
// (deny file* (subpath "/Users/vic8or"))

// ; Allow file write to Jupyter directory
// (allow file-read-data file-read-metadata
//     (subpath "/Users/vic8or/Library")
//     (subpath "/Users/vic8or/.local")
//     (literal "/Users/vic8or/dev/secure_notebook")
//     (subpath "/Users/vic8or/dev/secure_notebook")
//     (subpath "/Users/vic8or/dev/open")
//     (subpath "/Users/vic8or/dev/grunt")
//     (subpath "/Users/vic8or/dev/open-interpreter-tauri/src-tauri")
// )
// (allow file-write*
//     (subpath "/Users/vic8or/Library")
//     (subpath "/Users/vic8or/.local")
//     (subpath "/Users/vic8or/dev/secure_notebook")
// )
// ' jupyter-server
// ";
