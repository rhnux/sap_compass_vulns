#!/usr/bin/env python3
"""
CVE Data Collection Script
Collects and processes CVE data using SploitScan and CVE_Prioritizer tools.
"""

import argparse
import logging
import sys
import asyncio
from pathlib import Path
from typing import List, Tuple
from cve_prioritizer.cve_prioritizer import main as cve_main
from sploitscan.sploitscan import main as sploitscan_main

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('cve_processing.log')
    ]
)
logger = logging.getLogger(__name__)

class CVEDataProcessor:
    def __init__(self, input_file: str, output_file: str):
        self.input_file = Path(input_file)
        self.output_file = Path(output_file)
        self.validate_files()

    def validate_files(self) -> None:
        if not self.input_file.exists():
            raise FileNotFoundError(f"Input file does not exist: {self.input_file}")
        
        if not self.input_file.is_file():
            raise ValueError(f"Input path is not a file: {self.input_file}")
            
        self.output_file.parent.mkdir(parents=True, exist_ok=True)

    def read_cve_ids(self) -> List[str]:
        try:
            with self.input_file.open('r', encoding='utf-8') as f:
                cve_ids = [line.strip() for line in f if line.strip().startswith('CVE-')]
            
            if not cve_ids:
                raise ValueError("No valid CVE IDs found in input file")
                
            logger.info(f"Found {len(cve_ids)} valid CVE IDs")
            return cve_ids
            
        except Exception as e:
            logger.error(f"Error reading CVE IDs: {str(e)}")
            raise

    async def run_sploitscan(self) -> Tuple[bool, str]:
        try:
            cve_ids = self.read_cve_ids()
            logger.info("Starting SploitScan...")
            
            result = sploitscan_main(
                cve_ids=cve_ids,
                export_format='json',
                methods="cisa,epss,prio,references",
                debug=True
            )
            
            if result is False:
                return False, "SploitScan failed to process CVEs"
            return True, "SploitScan completed successfully"
            
        except Exception as e:
            return False, f"Error in SploitScan: {str(e)}"

    async def run_cve_prioritizer(self) -> Tuple[bool, str]:
        try:
            logger.info("Starting CVE_Prioritizer...")
            original_argv = sys.argv
            original_size = 0
            if self.output_file.exists():
                original_size = self.output_file.stat().st_size
            
            sys.argv = [
                'cve_prioritizer',
                '-f', str(self.input_file),
                '-vck',
                '-vc',
                '-v',
                '-t', '4',
                '-o', str(self.output_file)
            ]
            
            try:
                cve_main()
            except SystemExit:
                pass
            except Exception as e:
                return False, f"Error during CVE_Prioritizer execution: {str(e)}"
            finally:
                if self.output_file.exists():
                    current_size = self.output_file.stat().st_size
                    if current_size > original_size:
                        return True, f"CVE_Prioritizer completed successfully. Results saved in: {self.output_file}"
                
                return False, "CVE_Prioritizer did not generate results or output file is empty"
                
        finally:
            sys.argv = original_argv

    async def process(self) -> Tuple[bool, List[str]]:
        messages = []
        try:
            sploitscan_task = asyncio.create_task(self.run_sploitscan())
            prioritizer_task = asyncio.create_task(self.run_cve_prioritizer())

            sploitscan_success, sploitscan_msg = await sploitscan_task
            prioritizer_success, prioritizer_msg = await prioritizer_task
            
            if not sploitscan_success:
                logger.error(sploitscan_msg)
                messages.append(sploitscan_msg)
            else:
                logger.info(sploitscan_msg)
                messages.append(sploitscan_msg)
            
            if not prioritizer_success:
                logger.error(prioritizer_msg)
                messages.append(prioritizer_msg)
            else:
                logger.info(prioritizer_msg)
                messages.append(prioritizer_msg)
            
            return prioritizer_success and sploitscan_success, messages
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(error_msg)
            messages.append(error_msg)
            return False, messages

async def main():
    parser = argparse.ArgumentParser(
        description='Process CVEs using SploitScan and CVE_Prioritizer'
    )
    
    parser.add_argument(
        '-f', '--file',
        required=True,
        help='Input file containing CVE IDs'
    )
    
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output CSV file for CVE_Prioritizer results'
    )
    
    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help='Enable debug mode for detailed logging'
    )
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    try:
        processor = CVEDataProcessor(args.file, args.output)
        success, messages = await processor.process()
        
        # Exit with appropriate status code
        sys.exit(0 if success else 1)
            
    except Exception as e:
        logger.error(f"Fatal error during execution: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())