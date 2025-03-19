"""Stream new Reddit posts and notify for matching posts."""
import datetime
import os
import sys
import time

import apprise
import praw
import prawcore
import yaml

import logging
import argparse

from collections import Counter

CONFIG_PATH = os.getenv("RPN_CONFIG", "config.yml")
LOG_LEVEL = os.getenv("LOGLEVEL", "INFO")
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)
logger.addHandler(logging.StreamHandler(sys.stdout))

YAML_KEY_APPRISE = "apprise"
YAML_KEY_REDDIT = "reddit"
YAML_KEY_SUBREDDITS = "subreddits"
YAML_KEY_SUBREDDIT_CONTAINS = "contains"
YAML_KEY_SUBREDDIT_FILTER = "filter"
YAML_KEY_CLIENT = "client"
YAML_KEY_SECRET = "secret"
YAML_KEY_AGENT = "agent"
YAML_KEY_REDIRECT = "redirect"
YAML_KEY_LOGLEVEL = "loglevel"

do_notify=True
do_pass=False


def main():
    """Run application."""
    logger.info("Starting Reddit Post Notifier")
    args = parse_args()
    config = get_config()

    logger.setLevel(config[YAML_KEY_LOGLEVEL])
    logger.info(f"Logging at level {config[YAML_KEY_LOGLEVEL]}.")

    apprise_config = config[YAML_KEY_APPRISE]
    reddit_config = config[YAML_KEY_REDDIT]

    subreddits = reddit_config[YAML_KEY_SUBREDDITS]
    apprise_client = get_apprise_client(apprise_config)
    reddit_client = get_reddit_client(
        reddit_config[YAML_KEY_CLIENT],
        reddit_config[YAML_KEY_SECRET],
        reddit_config[YAML_KEY_AGENT],
        reddit_config[YAML_KEY_REDIRECT]
    )

    global do_notify
    do_notify = not args.no_notify

    global do_pass
    do_pass = not args.pass_always

    if not args.test_id:
        validate_subreddits(reddit_client, subreddits)
        stream_submissions(reddit_client, subreddits, apprise_client)
    else:
        process_submission(reddit_client.submission(id=args.test_id), subreddits, apprise_client)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--test-id', help='test reddit submission id')
    parser.add_argument('--no-notify', default=False, action='store_true', help='dont notify.')
    parser.add_argument('--pass-always', default=False, action='store_true', help='always pass testing post criteria.')

    return parser.parse_args()

def stream_submissions(reddit, subreddits, apprise_client):
    """Monitor and process new Reddit submissions in given subreddits."""
    subs = subreddits.keys()
    subs_joined = "+".join(subs)
    subreddit = reddit.subreddit(subs_joined)

    while True:
        try:
            for submission in subreddit.stream.submissions(pause_after=None, skip_existing=True):
                process_submission(submission, subreddits, apprise_client)

        except KeyboardInterrupt:
            sys.exit("\tStopping application, bye bye")

        except (praw.exceptions.PRAWException,
                prawcore.exceptions.PrawcoreException) as exception:
            logger.error("Reddit API Error: ")
            logger.error(exception)
            logger.error("Pausing for 30 seconds...")
            time.sleep(30)


def process_submission(submission, subreddits, apprise_client):
    """Notify if given submission matches search."""
    sub = submission.subreddit.display_name
    search_terms = subreddits[sub.lower()][YAML_KEY_SUBREDDIT_CONTAINS]
    filter_terms = subreddits[sub.lower()][YAML_KEY_SUBREDDIT_FILTER]

    tested_true, matched_keys = test_submission(submission, search_terms, filter_terms)

    if tested_true:
        if do_notify or do_pass:
            notify(apprise_client, submission, matched_keys)
            
def test_submission(submission, search_terms, filter_terms):
    match_candidates_dict = {}
    for attribute_key in 'link_flair_text', 'selftext', 'title':
        try:
            match_candidates_dict[attribute_key] = getattr(submission, attribute_key).lower()
        except AttributeError:
            pass
        else:
            break
    logger.debug(match_candidates_dict)

    submission_matched_keys = []
    submission_filtered_keys = []
    for candidate_key in match_candidates_dict.keys():
        if any(search_term in match_candidates_dict[candidate_key] for search_term in search_terms):
            submission_matched_keys.append(candidate_key)
        if filter_terms and any(filter_term in match_candidates_dict[candidate_key] for filter_term in filter_terms):
            submission_matched_keys.append(submission_filtered_keys)
    if len(submission_matched_keys) > 0:
        if len(submission_filtered_keys) > 0:
            for filter in submission_filtered_keys:
                logger.debug(f"Filtered submission[{submission}]: {filter}")
            return False
        for match in submission_matched_keys:
            logger.debug(f"Matched submission[{submission}]: {match}")
        return True, submission_matched_keys
    logger.debug(f"No Matches for {submission} {match_candidates_dict}")
    return False


    # match_candidates=[]
    # if submission.link_flair_text and not submission.link_flair_text == '':
    #     match_candidates.append(submission.link_flair_text.lower())
    # if submission.selftext and not submission.selftext == '':
    #     match_candidates.append(submission.selftext.lower())
    # if submission.title and not submission.title == '':
    #     match_candidates.append(submission.title.lower())
    # logger.debug(match_candidates)
    # submission_matched = False
    # submission_filtered = False
    # for candidate in match_candidates:
    #     if any(search_term in candidate for search_term in search_terms):
    #         submission_matched = True
    #     if filter_terms and any(filter_term in candidate for filter_term in filter_terms):
    #         submission_filtered = True
    # if submission_matched:
    #     if submission_filtered:
    #         logger.debug(f"Filtered submission[{submission}]: {candidate}")
    #         return False
    #     logger.debug(f"Matched submission[{submission}]: {candidate}")
    #     return True
    # logger.debug(f"No Matches for {submission} {match_candidates}")
    # return False


def notify(apprise_client, submission, matched_keys):
    """Send apprise notification."""
    title = submission.title
    author = submission.author
    pic='no pic' if submission.is_self else 'pic'
    
    body= f"{author.name} ({author.link_karma}/{author.comment_karma})[{pic}]\n"
    body+=f"Matched on: {matched_keys}\n"
    body+=f"https://www.reddit.com{submission.permalink}\n"
    body+= "---\n"
    body+=f"https://www.reddit.com/u/{submission.author.name}\n"
    body+= "---\n"
    body+=f"{summarize_posts(author)}"
    
    apprise_client.notify(
        title=title,
        body=body,
    )

    logger.info(f"{datetime.datetime.fromtimestamp(submission.created_utc)} r/{submission.subreddit.display_name}: {submission.title}")


def summarize_posts(author):
    posted_reddits = []
    for post in author.submissions.hot():
        posted_reddits.append(post.subreddit.display_name)
    sub_counts = Counter(posted_reddits)
    sub_summary = ''
    for posted_reddit in sub_counts.keys():
        sub_summary += f"{posted_reddit}: {sub_counts[posted_reddit]}\n"
    return sub_summary


def get_reddit_client(cid, secret, agent, redirect):
    """Return PRAW Reddit instance."""
    reddit = praw.Reddit(
        client_id=cid,
        client_secret=secret,
        user_agent=agent,
        redirect_uri=redirect
    )
    logger.info(reddit.auth.url(scopes=["identity"], state="...", duration="permanent"))
    return reddit


def get_apprise_client(config):
    """Return Apprise instance."""
    apprise_client = apprise.Apprise()

    for conf in config:
        apprise_client.add(conf)

    return apprise_client


def get_config():
    """Returns application configuration."""
    check_config_file()
    config = load_config()
    return validate_config(config)


def check_config_file():
    """Check if config file exists."""
    if not os.path.exists(CONFIG_PATH):
        sys.exit("Missing config file: " + CONFIG_PATH)

    logger.info("Using config file: " + CONFIG_PATH)


def load_config():
    """Load config into memory."""
    with open(CONFIG_PATH, "r") as config_yaml:
        config = None

        try:
            config = yaml.safe_load(config_yaml)

        except yaml.YAMLError as exception:
            if hasattr(exception, "problem_mark"):
                mark = exception.problem_mark # pylint: disable=no-member
                logger.error("Invalid yaml, line %s column %s" % (mark.line + 1, mark.column + 1))

            sys.exit("Invalid config: failed to parse yaml")

        if not config:
            sys.exit("Invalid config: empty file")

        return config


def validate_config(config):
    """Validate required config keys."""
    if YAML_KEY_REDDIT not in config or not isinstance(config[YAML_KEY_REDDIT], dict):
        sys.exit("Invalid config: missing reddit config")

    reddit = config[YAML_KEY_REDDIT]

    if YAML_KEY_CLIENT not in reddit or not isinstance(reddit[YAML_KEY_CLIENT], str):
        sys.exit("Invalid config: missing reddit -> client config")

    if YAML_KEY_SECRET not in reddit or not isinstance(reddit[YAML_KEY_SECRET], str):
        sys.exit("Invalid config: missing reddit -> secret config")

    if YAML_KEY_AGENT not in reddit or not isinstance(reddit[YAML_KEY_AGENT], str):
        sys.exit("Invalid config: missing reddit -> agent config")

    if YAML_KEY_SUBREDDITS not in reddit or not isinstance(reddit[YAML_KEY_SUBREDDITS], dict):
        sys.exit("Invalid config: missing reddit -> subreddits config")

    if YAML_KEY_APPRISE not in config or not isinstance(config[YAML_KEY_APPRISE], list):
        sys.exit("Invalid config: missing apprise config")

    logger.info("Monitoring Reddit for:")

    subs = reddit[YAML_KEY_SUBREDDITS]
    for subreddit_search_config_key in subs:
        logger.info(f"\tr/{subreddit_search_config_key}:")
        subreddit_search_config = subs[subreddit_search_config_key]

        if not subreddit_search_config[YAML_KEY_SUBREDDIT_CONTAINS] or not isinstance(subreddit_search_config[YAML_KEY_SUBREDDIT_CONTAINS], list):
            sys.exit(f"Invalid config: '{subreddit_search_config}' needs a list of search strings in 'contains'.")
        elif not all(isinstance(item, str) for item in subreddit_search_config[YAML_KEY_SUBREDDIT_CONTAINS]):
            sys.exit(f"Invalid config: '{subreddit_search_config}' needs a list of search strings in 'contains'.")
        else:
            subreddit_search_config[YAML_KEY_SUBREDDIT_CONTAINS] = [x.lower() for x in subreddit_search_config[YAML_KEY_SUBREDDIT_CONTAINS]]

        if subreddit_search_config[YAML_KEY_SUBREDDIT_FILTER] and not isinstance(subreddit_search_config[YAML_KEY_SUBREDDIT_FILTER], list):
            sys.exit(f"Invalid config: '{subreddit_search_config}' needs a list of search strings in 'filter' if used.")
        elif subreddit_search_config[YAML_KEY_SUBREDDIT_FILTER] and not all(isinstance(item, str) for item in subreddit_search_config[YAML_KEY_SUBREDDIT_FILTER]):
            sys.exit(f"Invalid config: '{subreddit_search_config}' needs a list of search strings in 'filter' if used.")
        else:
            subreddit_search_config[YAML_KEY_SUBREDDIT_FILTER] = [x.lower() for x in subreddit_search_config[YAML_KEY_SUBREDDIT_FILTER]]

        logger.info(f"\t\t Match:  {subreddit_search_config[YAML_KEY_SUBREDDIT_CONTAINS]}")
        logger.info(f"\t\t Filter: {subreddit_search_config[YAML_KEY_SUBREDDIT_FILTER]}")

    print("")
    reddit[YAML_KEY_SUBREDDITS] = {k.lower(): v for k, v in subs.items()}
    return config


def validate_subreddits(reddit, subreddits):
    """Validate subreddits."""
    for sub in subreddits:
        try:
            reddit.subreddit(sub).id

        except prawcore.exceptions.Redirect:
            sys.exit("Invalid Subreddit: " + sub)

        except (praw.exceptions.PRAWException,
                prawcore.exceptions.PrawcoreException) as exception:
            logger.error(f"[ {sub} ] Reddit API Error: ")
            logger.info(exception)


if __name__ == "__main__":
    main()
