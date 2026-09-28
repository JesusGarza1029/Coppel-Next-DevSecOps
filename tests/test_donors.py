def donor_payload():
    return {
        "name": "Ana Torres",
        "email": "ana@example.com",
        "phone": "8112345678",
        "blood_type": "O+",
    }


def test_user_can_create_donor(client, user_token):
    r = client.post("/donors", json=donor_payload(), headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 201
    assert r.json()["name"] == "Ana Torres"


def test_admin_can_list_donors(client, admin_token, user_token):
    client.post("/donors", json=donor_payload(), headers={"Authorization": f"Bearer {user_token}"})
    r = client.get("/donors", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert len(r.json()) == 1


def test_user_cannot_list_donors(client, user_token):
    r = client.get("/donors", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 403


def test_user_can_read_one_donor(client, user_token):
    created = client.post("/donors", json=donor_payload(), headers={"Authorization": f"Bearer {user_token}"}).json()
    r = client.get(f"/donors/{created['id']}", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 200


def test_admin_can_delete_donor(client, admin_token, user_token):
    created = client.post("/donors", json=donor_payload(), headers={"Authorization": f"Bearer {user_token}"}).json()
    r = client.delete(f"/donors/{created['id']}", headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 204
    assert client.get(f"/donors/{created['id']}", headers={"Authorization": f"Bearer {admin_token}"}).status_code == 404


def test_non_admin_cannot_delete(client, user_token):
    created = client.post("/donors", json=donor_payload(), headers={"Authorization": f"Bearer {user_token}"}).json()
    r = client.delete(f"/donors/{created['id']}", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 403


def test_xss_is_escaped(client, user_token):
    payload = donor_payload() | {"name": "<script>alert('x')</script>"}
    r = client.post("/donors", json=payload, headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 201
    assert "<script>" not in r.json()["name"]
    assert "&lt;script&gt;" in r.json()["name"]


def test_sqli_payload_does_not_return_all_rows(client, admin_token, user_token):
    for i in range(2):
        client.post(
            "/donors",
            json=donor_payload() | {"name": f"Donante {i}"},
            headers={"Authorization": f"Bearer {user_token}"},
        )
    payload = "' OR 1=1 --"
    r = client.get("/donors", params={"q": payload}, headers={"Authorization": f"Bearer {admin_token}"})
    assert r.status_code == 200
    assert r.json() == []


def test_missing_donor_returns_404(client, user_token):
    r = client.get("/donors/9999", headers={"Authorization": f"Bearer {user_token}"})
    assert r.status_code == 404
