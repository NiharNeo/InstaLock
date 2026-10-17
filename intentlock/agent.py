"""Compatibility entrypoint for the isolated, redacted Gemini proposal worker."""
from app.agent.worker import main

if __name__=='__main__':
    main()
