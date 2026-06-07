use pyo3::prelude::*;

#[pymodule]
fn _pyopenssl_shim(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    pyopenssl::populate_module(py, m)
}
