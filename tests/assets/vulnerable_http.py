import requests
import subprocess


def run_command(cmd):
    return subprocess.run(cmd, shell=True)


def fetch_url(url):
    return requests.get(url)

