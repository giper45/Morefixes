import re


CATEGORY_RULES = {
    "WordPress": [r"wordpress", r"wp-"],
    "Joomla": [r"joomla"],
    "Linux Kernel": [r"linux kernel", r"torvalds/linux", r"kernel"],
    "Drupal": [r"drupal"],
    "Magento": [r"magento"],
    "Moodle": [r"moodle"],
    "Apache": [r"apache"],
    "GitLab": [r"gitlab"],
    "GitHub": [r"github"],
    "Docker": [r"docker"],
    "Kubernetes": [r"kubernetes", r"k8s"],
}


def infer_category(repo_url: str | None, description: str | None) -> str:
    haystack = f"{repo_url or ''} {description or ''}".lower()
    for category, patterns in CATEGORY_RULES.items():
        if any(re.search(pattern, haystack) for pattern in patterns):
            return category
    return "Other"
