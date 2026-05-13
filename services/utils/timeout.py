from concurrent.futures import ThreadPoolExecutor, TimeoutError

def run_with_timeout(fn, seconds, *args, **kwargs):
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(fn, *args, **kwargs)
        try:
            return future.result(timeout=seconds)
        except TimeoutError:
            return None
