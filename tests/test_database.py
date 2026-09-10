from pathlib import Path

from main import AuthApp, UserDatabase


def profile(cpf="52998224725"):
    return {
        "cpf": cpf, "cep": "01001000", "logradouro": "Praca da Se",
        "numero": "1", "complemento": "", "bairro": "Se", "cidade": "Sao Paulo",
        "uf": "SP", "foto_path": "", "estado_civil": "Solteiro(a)", "cor_pele": "Parda",
    }


def test_cpf_and_password_rules():
    assert AuthApp._is_valid_cpf("529.982.247-25")
    assert not AuthApp._is_valid_cpf("111.111.111-11")
    assert AuthApp._is_strong_password("Senha123")
    assert not AuthApp._is_strong_password("senha123")


def test_register_authenticate_update_and_export(tmp_path: Path):
    database = UserDatabase(tmp_path / "users.db")
    assert database.create_user("admin", "Senha123", profile())
    assert database.get_user("admin")["papel"] == "admin"
    assert database.authenticate("admin", "Senha123")[0]
    assert not database.authenticate("admin", "errada")[0]
    data = profile("11144477735")
    assert database.create_user("ana", "Senha123", data)
    data["cidade"] = "Campinas"
    assert database.update_user("ana", data)
    assert database.get_user("ana")["cidade"] == "Campinas"
    output = tmp_path / "usuarios.csv"
    assert database.export_csv(str(output)) == 2
    assert output.exists()


def test_disable_user(tmp_path: Path):
    database = UserDatabase(tmp_path / "users.db")
    database.create_user("admin", "Senha123", profile())
    database.set_active("admin", False)
    assert not database.authenticate("admin", "Senha123")[0]
