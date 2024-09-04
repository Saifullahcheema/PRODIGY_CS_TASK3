import re

def assess_password_strength(password):
    # Define the criteria for complexity
    min_length = 8
    has_uppercase = re.compile(r'[A-Z]')
    has_lowercase = re.compile(r'[a-z]')
    has_digit = re.compile(r'\d')
    has_special = re.compile(r'[!@#$%^&*()_+{}\[\]:;"\'<>,.?/\\|`~]')
    
    # Check length
    length_score = len(password) >= min_length
    
    # Check different character types
    uppercase_score = bool(has_uppercase.search(password))
    lowercase_score = bool(has_lowercase.search(password))
    digit_score = bool(has_digit.search(password))
    special_score = bool(has_special.search(password))
    
    # Calculate overall score
    total_score = sum([length_score, uppercase_score, lowercase_score, digit_score, special_score])
    
    # Determine strength based on score
    if total_score == 5:
        strength = "Very Strong"
    elif total_score == 4:
        strength = "Strong"
    elif total_score == 3:
        strength = "Moderate"
    elif total_score == 2:
        strength = "Weak"
    else:
        strength = "Very Weak"
    
    # Generate feedback
    feedback = []
    if not length_score:
        feedback.append("Password must be at least 8 characters long.")
    if not uppercase_score:
        feedback.append("Password must include at least one uppercase letter.")
    if not lowercase_score:
        feedback.append("Password must include at least one lowercase letter.")
    if not digit_score:
        feedback.append("Password must include at least one digit.")
    if not special_score:
        feedback.append("Password must include at least one special character.")
    
    return strength, feedback

# Example usage
def main():
    password = input("Enter your password: ")
    strength, feedback = assess_password_strength(password)
    
    print(f"Password Strength: {strength}")
    if feedback:
        print("Feedback:")
        for line in feedback:
            print(f" - {line}")

if __name__ == "__main__":
    main()
