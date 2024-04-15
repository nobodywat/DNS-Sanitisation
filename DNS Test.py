import subprocess

def run_dig_command(domain):
    try:
        # Running the dig command for the given domain
        result = subprocess.run(['dig', '+short', domain], capture_output=True, text=True)
        if result.stdout.strip():
            return result.stdout  # Return the standard output of the dig command if not empty
        else:
            return "No IP found"  # Return message if no IP is resolved
    except Exception as e:
        return f"An error occurred while running dig: {e}"

# Reading the domain names from the resolved domains file and running dig on each
try:
    with open("resolved_domains.txt", "r") as file:
        domains = file.readlines()

    for line in domains:
        domain = line.split(':')[0].strip()  # Extract the domain name from each line
        output = run_dig_command(domain)
        print(f'Dig results for {domain}:\n{output}')

except FileNotFoundError:
    print("The file 'resolved_domains.txt' does not exist.")
except Exception as e:
    print(f"An error occurred: {e}")