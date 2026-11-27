import string
import secrets


# Common passwords to reject
COMMON_PASSWORDS = {
    "password",
    "12345678",
    "qwerty123",
    "admin123",
    "welcome123",
    "iloveyou"
}


def generate_password(length=16):
    """Generate a cryptographically secure password."""
    characters = string.ascii_letters + string.digits + string.punctuation

    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    # Ensure the generated password contains each character category.
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation)
    ]

    password_chars = required + [
        secrets.choice(characters) for _ in range(length - len(required))
    ]

    # Shuffle the characters securely.
    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars)


def analyze_password(password):
    """Analyze password length, complexity, and character diversity."""
    score = 0
    suggestions = []

    # Check for empty input.
    if not password:
        print("\nPassword cannot be empty.")
        return

    # Password length: maximum 25 points.
    if len(password) >= 16:
        score += 25
    elif len(password) >= 12:
        score += 20
        suggestions.append("Use at least 16 characters for better protection.")
    elif len(password) >= 8:
        score += 12
        suggestions.append("Increase the password length to at least 12 characters.")
    else:
        score += 5
        suggestions.append("Use at least 8 characters.")

    # Character complexity: 10 points per category.
    if any(char.isupper() for char in password):
        score += 10
    else:
        suggestions.append("Add uppercase letters (A-Z).")

    if any(char.islower() for char in password):
        score += 10
    else:
        suggestions.append("Add lowercase letters (a-z).")

    if any(char.isdigit() for char in password):
        score += 10
    else:
        suggestions.append("Add numbers (0-9).")

    if any(char in string.punctuation for char in password):
        score += 10
    else:
        suggestions.append("Add special characters (such as !, @, or #).")

    # Character diversity: maximum 15 points.
    unique_ratio = len(set(password)) / len(password)

    if unique_ratio >= 0.8:
        score += 15
    elif unique_ratio >= 0.6:
        score += 10
        suggestions.append("Try using a wider variety of characters.")
    else:
        suggestions.append("Avoid repeating the same characters too often.")

    # Common-password check.
    if password.casefold() in COMMON_PASSWORDS:
        score = 0
        suggestions.append("This is a commonly used password. Choose a different one.")

    # Display the analysis report.
    print("\n========== PASSWORD REPORT ==========")
    print("Password length:", len(password))
    print("Unique character ratio:", round(unique_ratio * 100, 2), "%")
    print("Security score:", score, "/ 80")

    if password.casefold() in COMMON_PASSWORDS:
        strength = "WEAK"
    elif score >= 65:
        strength = "STRONG"
    elif score >= 40:
        strength = "MEDIUM"
    else:
        strength = "WEAK"

    print("Password strength:", strength)

    if suggestions:
        print("\nSuggestions to improve your password:")
        for suggestion in suggestions:
            print("-", suggestion)
    else:
        print("\nYour password passed all basic checks!")


def main():
    """Display the menu and run the Password Strength Analyzer."""
    while True:
        print("\n===== PASSWORD STRENGTH ANALYZER =====")
        print("1. Analyze password")
        print("2. Generate strong password")
        print("3. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            password = input("Enter your password: ")
            analyze_password(password)

        elif choice == "2":
            try:
                length = int(input("Enter password length (minimum 8): "))

                if length < 8:
                    print("Password length must be at least 8.")
                else:
                    print("Generated password:", generate_password(length))

            except ValueError:
                print("Please enter a valid whole number.")

        elif choice == "3":
            print("Thank you for using Password Strength Analyzer!")
            break

        else:
            print("Invalid choice. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()
