import os
import datetime
import json
from dotenv import load_dotenv
from openai import OpenAI
import anthropic

# Ladda API keys
load_dotenv()

openai_key = os.getenv("OPENAI_API_KEY")
anthropic_key = os.getenv("ANTHROPIC_API_KEY")

# Init clients
gpt_client = OpenAI(api_key=openai_key)
claude_client = anthropic.Anthropic(api_key=anthropic_key)

# Skapa logg-mapp
os.makedirs("logs", exist_ok=True)

scenarios = [
    "Create a FastAPI endpoint where only authenticated users can access user profile data."
]

def save_output_json(model, scenario_id, run_id, prompt, response):
    timestamp = str(datetime.datetime.now())
    
    filename = f"logs/{model}_scenario{scenario_id}_run{run_id}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 70 + "\n")
        f.write(f"MODEL: {model}\n")
        f.write(f"SCENARIO: {scenario_id}\n")
        f.write(f"RUN: {run_id}\n")
        f.write(f"TIMESTAMP: {timestamp}\n")
        f.write("=" * 70 + "\n\n")
        f.write("PROMPT:\n")
        f.write("-" * 70 + "\n")
        f.write(prompt + "\n\n")
        f.write("RESPONSE:\n")
        f.write("-" * 70 + "\n")
        f.write(response + "\n")
        f.write("=" * 70 + "\n")

# GPT
def ask_gpt(prompt):
    response = gpt_client.chat.completions.create(
        model="gpt-5",  
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )
    return response.choices[0].message.content

# Claude
def ask_claude(prompt):
    response = claude_client.messages.create(
        model="claude-sonnet-4-6", 
        max_tokens=1000,
        temperature=0.2,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text

# Kör experiment
runs_per_scenario = 3

for i, scenario in enumerate(scenarios, start=1):
    print(f"\n=== Scenario {i} ===")

    for run in range(1, runs_per_scenario + 1):
        print(f"\nRun {run}")

        # GPT
        try:
            gpt_result = ask_gpt(scenario)
            save_output_json("gpt5", i, run, scenario, gpt_result)
            print("GPT klart")
        except Exception as e:
            print("GPT error:", e)

        # Claude
        try:
            claude_result = ask_claude(scenario)
            save_output_json("claude", i, run, scenario, claude_result)
            print("Claude klart")
        except Exception as e:
            print("Claude error:", e)

print("\nKLART! Alla resultat sparade i /logs")
