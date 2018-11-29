import requests
import json
import argparse
from bs4 import BeautifulSoup
import re
import subprocess
import os
from time import sleep
from threading import Thread

secrets_dict = {
    "aws_secret_key": "[0-9a-zA-Z\\\/\+\=]{40}",
    "bindpw": "bindpw [a-zA-Z0-9\@\-\.\!\?\\\/\$\=]+"
}

max_threads = 1
cur_threads = 0

def parse_cookie_file(filepath):
    """
    Creates a requests.cookies.RequestsCookieJar based
    on a firefox addon's cookie export feature.

    :param filepath: Path to cookies.json file.
    :return: requests.cookies.RequestsCookieJar
    """
    with open(filepath, 'r') as f:
        cookies_json = json.loads(f.read())
    jar = requests.cookies.RequestsCookieJar()
    for cookie in cookies_json["cookies"]:
        jar.set(cookie["name"], cookie["value"], domain=cookie["domain"], path=cookie["path"], secure=cookie["secure"], rest={'HttpOnly': cookie['httpOnly']})

    return jar

def max_pages(soup):
    """
    Determine the maximum number of search results.

    :param soup: BeautifulSoup object of Github search page.
    :return: int
    """
    pagination_div = soup.findAll("div", {"class": "pagination"})

    for tag in pagination_div:
        hyperlinks = tag.find_all("a")
        for a in hyperlinks:
            # print(a.get_text())
            if a.get_text() == "Next":
                return int(hyperlinks[hyperlinks.index(a) - 1].get_text())

    return 1


def normalize_url(domain):
    if "http://" not in domain and "https://" not in domain:
        domain = "https://" + domain
    if domain[-1] == "/":
        domain = domain[:-1]
    return domain

def parse_code_page(key, regex, soup, base_url):
    """
    Given a search word (key) and regex value, search the Github
    search results page (soup) for the regex matching key.

    :param key: A search term.
    :param regex: A regex value that indicates a positive match.
    :param soup: A BeautifulSoup object of the Github search result page.
    :return: dict
    """
    results = {key: []}
    code_list_items = soup.findAll("div", {"class": "code-list-item"})
    # print("Items: {}".format(len(code_list_items)))
    i = 0
    for item in code_list_items:
        path = ""
        # divs = item.findAll("div", {"class": "d-inline-block col-10"})
        divs = item.findAll("div", {"class": "file-box blob-wrapper"})
        i += 1
        # print("On item: {}, fileboxes: {}".format(i, len(divs)))
        for d in divs:
            path = d.find("a").get("href")
            code_blobs = d.findAll("td", {"class":"blob-code blob-code-inner"})
            # print(len(code_blobs))
            for blob in code_blobs:
                blob_code = blob.decode_contents()
                search = re.findall(regex, blob_code)
                # print("Regex: {}".format(regex))
                # print("Search results: {}".format(len(search)))
                # if "bindpw" in blob_code:
                #     print(blob_code)
                if len(search) > 0:
                    url = base_url + path
                    print("Found potential {} at {}: {}".format(key, url, search[0]))
                    secret = search[0]
                    if key == "aws_secret_key":
                        search = re.findall("AKIA[0-9A-Z]{16}", blob_code)
                        if len(search) > 0:
                            print("aws_access_key: {}".format(search[0]))
                            print("aws_secret_key: {}".format(secret))
                    search_item = {
                        "url": url,
                        "snippet": blob_code,
                        "value": secret
                    }
                    results[key].append(search_item)
    return results

def write_results(results, outfile):
    header = "########################################"
    with open(outfile, "w") as f:
        for regex, items in results.items():
            spaces_count = len(header) - len(regex) - 4
            f.write(header + "\n")
            f.write("# " + " " * int(spaces_count / 2) + regex + " " * int(spaces_count / 2) + " #\n")
            f.write(header + "\n\n")
            for item in items:
                f.write("URL: {}\n".format(item["url"]))
                f.write("Value: {}\n".format(item["value"]))
                f.write("Snippet: {}\n\n".format(item["snippet"]))
                f.write("-" * 20)
                f.write("\n\n")
    print("[+] Results written to {}".format(outfile))

def parse_repo_links(soup, base_url):
    """
    Return all hyperlinks to repositories on a github page.

    :param soup: BeautifulSoup object of a page on a user repository.
    :return: Links.
    """

    domain = base_url.split("/")[2]
    # for d in repo_list:
    ssh_url = "git@{}:{}"
    hrefs = [ssh_url.format(domain, x.get("href")[1:]) for x in soup.findAll("a", {"itemprop": "name codeRepository"})]
    return(hrefs)

def find_local_repos():
    """

    :return: List of file paths to git directories.
    """
    d = '.'
    dir_path = os.path.realpath(d)
    # print("Dir path: {}".format(dir_path))
    partial_git_dirs = [os.path.join(d, o)[1:] for o in os.listdir(d) if os.path.isdir(os.path.join(d, o)) and ".git" in os.listdir(os.path.join(d,o))]
    # print("Partial git dirs: {}".format(partial_git_dirs))
    git_dirs = [dir_path + x for x in partial_git_dirs]
    return git_dirs

def git_clone(href):
    global cur_threads
    if href[-4:] != ".git":
        href += ".git"
    try:
        with open("/dev/null","w") as devnull:
            subprocess.run(["git","clone",href], stdout=devnull, stderr=devnull)
            print("[+] Cloned {} sucessfully.".format(href))
    except subprocess.CalledProcessError:
        print("[-] Failed to clone repository at: {}".format(href))
    cur_threads -= 1

def trufflehog(repo, outdir):
    """
    Runs trufflehog on a list of git repositories.

    :param repos: List of filepaths to git directories.
    :return: None
    """
    if outdir[-1] != "/":
        outdir += "/"

    repo_name = repo.split("/")[-1]
    try:
        cmd = subprocess.run(["trufflehog", "file://{}".format(repo)], stdout=subprocess.PIPE)
        outfile = outdir + repo_name + ".trufflehog"
        with open(outfile, 'wb') as f:
            f.write(cmd.stdout)
        print("[+] Analyzed repo: {}".format(repo_name))
    except Exception as e:
        print("Error in running trufflehog. Reason: {}".format(e))
    global cur_threads
    cur_threads -= 1

def del_repos(repos):
    """
    Remove a list of directories.
    :param repos: List of directory strings.
    :return: None
    """
    for repo in repos:
        try:
            subprocess.run(["rm", "-rf", repo])
        except subprocess.CalledProcessError:
            print("[!] Could not delete repo: {}".format(repo))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cookies_json", help="Cookies json file from FireFox extension Cookie Manager by Rob W.")
    parser.add_argument("github_url", help="Github URL you wish to crawl.")
    # parser.add_argument("outfile", nargs='?', default="search_results.txt", help="Output file to write results.")
    args = parser.parse_args()
    # https://github.com/search?o=desc&p=17&q=aws_secret_key&s=indexed&type=Code
    if not args.cookies_json or not args.github_url:
        raise Exception("Require both cookies.json and github base url to begin search.")
    jar = parse_cookie_file(args.cookies_json)
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
    }
    base_url = normalize_url(args.github_url)
    # p = page number, q = query
    # search_url = base_url + "/search?o=desc&p={}&q={}&s=indexed&type=Code"
    s = requests.Session()
    s.cookies.update(jar)
    s.headers.update(headers)

    print("Fetching user repositories from: {}".format(base_url))
    repo_url = base_url + "?tab=repositories"
    r = requests.get(repo_url, cookies=jar, headers=headers, verify=False)
    # with open(args.outfile, 'w') as f:
    #     f.write(r.content)

    # with open("test.hml", "r") as f:
    #     soup = BeautifulSoup(f.read(), 'html.parser')
    soup = BeautifulSoup(r.content, 'html.parser')
    repo_list = soup.find("div", {"class": "org-repos repo-list"})

    th_dir = "trufflehog/"
    outdir = th_dir + base_url.split("/")[-1]
    max = max_pages(soup)
    try:
        os.mkdir(th_dir)
    except Exception as e:
        # print(e)
        pass
    try:
        os.mkdir(outdir)
    except Exception as e:
        pass

    global max_threads, cur_threads
    print("Max pages: {}".format(max))
    for i in range(1, max+1):
        r = requests.get(repo_url + "&page={}".format(i), cookies=jar, headers=headers, verify=False)
        soup = BeautifulSoup(r.content, 'html.parser')
        hrefs = parse_repo_links(soup, base_url)
        for href in hrefs:
            while True:
                if cur_threads < max_threads:
                    t = Thread(target=git_clone, args=(href,))
                    cur_threads += 1
                    t.start()
                    break
                sleep(5)
        while cur_threads != 0:
            print("Number of threads still cloning: {}".format(cur_threads))
            sleep(5)
        new_repos = find_local_repos()
        for repo in new_repos:
            while True:
                if cur_threads < max_threads:
                    t = Thread(target=trufflehog, args=(repo, outdir))
                    cur_threads += 1
                    t.start()
                    break
                sleep(5)
        while cur_threads != 0:
            print("[.] Number of threads still trufflehoggin': {}".format(cur_threads))
            sleep(10)
        del_repos(new_repos)





    # results = {x: [] for x in secrets_dict}

    # for key, regex in secrets_dict.items():
    #     try:
    #         url = search_url.format(1, key)
    #         r = s.get(url)
    #         soup = BeautifulSoup(r.content, 'html.parser')
    #         max_len = max_pages(soup)
    #         print("{} Pages of results for key: {}".format(max_len, key))
    #         search_results = parse_code_page(key, regex, soup, base_url)
    #         results[key] += search_results[key]
    #         for i in range(2, max_len+1):
    #             try:
    #                 url = search_url.format(i, key)
    #                 r = s.get(url)
    #                 soup = BeautifulSoup(r.content, 'html.parser')
    #                 # print("URL is: {}".format(url))
    #                 search_results = parse_code_page(key, regex, soup, base_url)
    #                 results[key] += search_results[key]
    #             except Exception as e:
    #                 print("Error occured while iterating through search results: {}".format(e))
    #     except Exception as e:
    #         print("Error occured while cycling through regexes: {}".format(e))
    #
    # # print(results)
    # for k in results.keys():
    #     print("Found {} {}s".format(len(results[k]), k))
    #
    # write_results(results, args.outfile)

if __name__ == "__main__":
    main()
