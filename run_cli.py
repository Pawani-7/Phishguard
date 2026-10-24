"""PhishGuard command-line tool.

Type a link and see its risk level and the reasons .
The link is only analysed as text. It is never opened.
"""

from scoring import analyse


def main():
    print("PhishGuard: type a link to check it (type q to quiet)")
    print("Links are analysed as text only and are never opened.")
    while True:
        url = input("n/Link: ").strip()
        if url.lower() in ("q", "quit", "exit"):
            print("Goodbye.")
            break
        result = analyse(url)
        print(f"Risk level: {result['level']} (score {result['score']})")
        if result["reasons"]:
            print("Reasons:")
            for reason in result["reasons"]:
                print(f"   - {reason}")
        else:
            print("No warning signs found in the link text.")


if __name__ =="__main__":
    main()