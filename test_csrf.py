from app import app

app.config["TESTING"] = True

with app.test_client() as client:
    response = client.post(
        "/logout",
        follow_redirects=False
    )

    print("Status code:", response.status_code)
    print("Response:", response.get_data(as_text=True)[:300])