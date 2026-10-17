"""Run the trusted pending-operation reconciler independently of request workers."""
import argparse
import logging
import time
from app.core.receipts import load_receipt_key
from app.core.policy import PolicyEngine
from app.executor.config import ExecutorSettings
from app.executor.razorpay import RazorpayTestAdapter
from app.executor.service import ExecutorService
from intentlock.db import engine_for


def main() -> None:
    """Query pending operations older than 60s, once or every 15 seconds."""
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--once',action='store_true')
    args=parser.parse_args()
    config=ExecutorSettings.from_env()
    load_receipt_key()
    engine=engine_for(config.database_url)
    provider=RazorpayTestAdapter(config)
    service=ExecutorService(engine,config,PolicyEngine.load(config.policy_file),provider)
    try:
        while True:
            try:
                service.reconcile()
            except Exception:
                logging.error('Reconciliation unavailable; pending operations remain reserved')
                if args.once:
                    raise
            if args.once:
                return
            time.sleep(15)
    finally:
        provider.close()
        engine.dispose()


if __name__=='__main__':
    main()
