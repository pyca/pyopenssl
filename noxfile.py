import nox

nox.options.reuse_existing_virtualenvs = True
nox.options.default_venv_backend = "uv|virtualenv"

MINIMUM_CRYPTOGRAPHY_VERSION = "46.0.0"


@nox.session
@nox.session(name="tests-cryptography-main")
@nox.session(name="tests-cryptography-minimum")
@nox.session(name="tests-wheel")
@nox.session(name="tests-cryptography-minimum-wheel")
@nox.session(name="tests-random-order")
def tests(session: nox.Session) -> None:
    cryptography_version = None
    use_wheel = False
    random_order = False

    if "cryptography-main" in session.name:
        cryptography_version = "main"
    elif "cryptography-minimum" in session.name:
        cryptography_version = "minimum"

    if "wheel" in session.name:
        use_wheel = True

    if "random-order" in session.name:
        random_order = True

    deps = ["coverage>=4.2"]

    if cryptography_version == "minimum":
        deps.append(f"cryptography=={MINIMUM_CRYPTOGRAPHY_VERSION}")

    if random_order:
        deps.append("pytest-randomly")

    extra_install_args = []
    if not use_wheel:
        extra_install_args.append("--no-binary")
        extra_install_args.append("cryptography")

    session.install(*deps)
    session.install("-e", ".[test]", *extra_install_args)
    if cryptography_version == "main":
        session.install("git+https://github.com/pyca/cryptography.git")

    session.run("openssl", "version", external=True)
    session.run("coverage", "run", "--parallel", "-m", "OpenSSL.debug")
    session.run(
        "coverage", "run", "--parallel", "-m", "pytest", "-v", *session.posargs
    )


@nox.session
def lint(session: nox.Session) -> None:
    session.install("ruff")
    session.run("ruff", "check", ".")
    session.run("ruff", "format", "--check", ".")


@nox.session
def mypy(session: nox.Session) -> None:
    session.install("-e", ".[test]")
    session.install("mypy")
    session.run("mypy", "src/", "tests/")


@nox.session(name="check-manifest")
def check_manifest(session: nox.Session) -> None:
    session.install("check-manifest")
    session.run("check-manifest")


@nox.session
def docs(session: nox.Session) -> None:
    session.install("-e", ".[docs]")
    session.run(
        "sphinx-build",
        "-W",
        "-b",
        "html",
        "doc",
        "doc/_build/html",
        *session.posargs,
    )
