import os
from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_openai import ChatOpenAI

from app.tools import detect_iocs, map_tactics
from app.schema import IncidentReport

load_dotenv()


def build_agent():
    model = ChatOpenAI(
        model=os.getenv("AI_MODEL"),
        base_url=os.getenv("AI_ENDPOINT"),
        api_key=os.getenv("AI_API_KEY"),
    )

    agent = create_agent(
        model=model,
        tools=[detect_iocs, map_tactics],
        system_prompt=(
    "You are a defensive cybersecurity SOC analyst. "
    "Analyze the provided log text conservatively. "
    "You must use the available tools to detect indicators and map tactics. "
    "The 'indicators' field must contain the exact indicator labels returned by the detection tool. "
    "The 'tactics' field must contain only the tactic names returned by the mapping tool, such as "
    "'Credential Access', 'Initial Access', or 'Execution'. "
    "Do not invent new indicator names or tactic names. "
    "Return a structured incident report. "
    "Do not provide offensive guidance or exploitation steps. "
    "If evidence is weak or ambiguous, use needs_review."
),
        response_format=IncidentReport,
    )
    return agent
