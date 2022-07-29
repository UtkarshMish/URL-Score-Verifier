from csv import DictWriter
from dataclasses import asdict, dataclass
from os import environ
from typing import Dict, List, Union

from dotenv import load_dotenv
from virustotal3.core import URL

load_dotenv(".env")


@dataclass(init=True, eq=True, frozen=True, order=True, repr=True)
class Analysis:
    harmless: int
    malicious: int
    suspicious: int
    undetected: int
    timeout: int

    @property
    def result(self):
        max_val = max(*asdict(self).values())
        if max_val == self.harmless:
            return "harmless"
        elif max_val == self.malicious:
            return "malicious"
        elif max_val == self.suspicious:
            return "suspicious"
        elif max_val == self.timeout:
            return "Not verified"


class VirusTotalHandler:

    API_KEY = environ.get("API_KEY")

    @staticmethod
    def fetch_links(file_name: str):
        return open(file_name, "r", encoding="utf8").readlines()

    @staticmethod
    def verify_links(links_data: List[str]) -> List[Dict[str, Union[str, int]]]:
        result_data: List[Dict[str, Union[str, int]]] = list()
        url_info = URL(VirusTotalHandler.API_KEY)
        for links in links_data:
            result: Dict[str, str] = url_info.info_url(links)
            analysis_stats = Analysis(
                **(result["data"]["attributes"]["last_analysis_stats"])
            )

            result_data.append(
                {
                    "link": links,
                    **asdict(analysis_stats),
                    "conclusion": analysis_stats.result,
                }
            )

        return result_data

    @staticmethod
    def write_to_csv(filename: str, data: List[Dict[str, Union[str, int]]]):
        writer = DictWriter(
            open(filename, "w", encoding="utf8", newline=""),
            doublequote=True,
            fieldnames=[
                "link",
                *list(Analysis.__dataclass_fields__.keys()),
                "conclusion",
            ],
        )
        writer.writeheader()
        writer.writerows(data)


if __name__ == "__main__":
    file_name = "input.txt"
    result_file_name = "output.csv"
    print("--" * 7, "URL Score Verify", "--" * 7)
    print("INFO:", "fetching links from", file_name)
    links_data = VirusTotalHandler.fetch_links(file_name)
    print("INFO:", "Verifying links ...")
    info_result = VirusTotalHandler.verify_links(links_data)
    print("INFO:", "writing result to ", result_file_name)
    VirusTotalHandler.write_to_csv(result_file_name, info_result)
    print("--" * 10, "COMPLETED", "--" * 10)
