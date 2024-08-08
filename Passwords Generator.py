import secrets
import string
import re
from typing import List, Tuple

class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate_password(self, length: int = 16, 
                          min_lowercase: int = 1, 
                          min_uppercase: int = 1, 
                          min_digits: int = 1, 
                          min_special: int = 1) -> str:
        if length < (min_lowercase + min_uppercase + min_digits + min_special):
            raise ValueError("Minimum requirements exceed password length")

        all_chars = self.lowercase + self.uppercase + self.digits + self.special_chars
        
        password = (
            ''.join(secrets.choice(self.lowercase) for _ in range(min_lowercase)) +
            ''.join(secrets.choice(self.uppercase) for _ in range(min_uppercase)) +
            ''.join(secrets.choice(self.digits) for _ in range(min_digits)) +
            ''.join(secrets.choice(self.special_chars) for _ in range(min_special))
        )
        
        remaining_length = length - len(password)
        password += ''.join(secrets.choice(all_chars) for _ in range(remaining_length))
        
        password_list = list(password)
        secrets.SystemRandom().shuffle(password_list)
        return ''.join(password_list)

    def generate_multiple_passwords(self, count: int, **kwargs) -> List[str]:
        return [self.generate_password(**kwargs) for _ in range(count)]

    def estimate_password_strength(self, password: str) -> Tuple[float, str]:
        entropy = 0
        if re.search(r'[a-z]', password):
            entropy += len(self.lowercase)
        if re.search(r'[A-Z]', password):
            entropy += len(self.uppercase)
        if re.search(r'\d', password):
            entropy += len(self.digits)
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            entropy += len(self.special_chars)
        
        bit_strength = len(password) * (entropy.bit_length() - 1)
        
        if bit_strength < 64:
            strength = "Weak"
        elif bit_strength < 80:
            strength = "Moderate"
        elif bit_strength < 112:
            strength = "Strong"
        else:
            strength = "Very Strong"
        
        return bit_strength, strength

def get_integer_input(prompt: str, min_value: int = 0) -> int:
    while True:
        try:
            value = int(input(prompt))
            if value < min_value:
                print(f"Please enter a number greater than or equal to {min_value}.")
            else:
                return value
        except ValueError:
            print("Please enter a valid integer.")

def main():
    generator = PasswordGenerator()
    
    while True:
        print("\n--- Advanced Password Generator ---")
        print("1. Generate a single password")
        print("2. Generate multiple passwords")
        print("3. Estimate password strength")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            length = get_integer_input("Enter password length (minimum 8): ", 8)
            min_lowercase = get_integer_input("Enter minimum lowercase characters: ")
            min_uppercase = get_integer_input("Enter minimum uppercase characters: ")
            min_digits = get_integer_input("Enter minimum digits: ")
            min_special = get_integer_input("Enter minimum special characters: ")
            
            try:
                password = generator.generate_password(length, min_lowercase, min_uppercase, min_digits, min_special)
                print(f"\nGenerated Password: {password}")
                bit_strength, strength = generator.estimate_password_strength(password)
                print(f"Password Strength: {strength} ({bit_strength:.2f} bits)")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == '2':
            count = get_integer_input("Enter the number of passwords to generate: ", 1)
            length = get_integer_input("Enter password length (minimum 8): ", 8)
            
            passwords = generator.generate_multiple_passwords(count, length=length)
            print("\nGenerated Passwords:")
            for idx, pwd in enumerate(passwords, 1):
                print(f"{idx}. {pwd}")
        
        elif choice == '3':
            password = input("Enter the password to estimate strength: ")
            bit_strength, strength = generator.estimate_password_strength(password)
            print(f"Password Strength: {strength} ({bit_strength:.2f} bits)")
        
        elif choice == '4':
            print("Thank you for using the Advanced Password Generator. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()