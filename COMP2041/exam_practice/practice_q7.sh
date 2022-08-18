#! /bin/dash

if [ ! "$(git status 2>/dev/null)" ]; then
    echo "$0: Not a git repository"
    exit 1
fi

if [ "$(echo git log | wc -l)" -eq 0 ]; then
    echo "$0: No commits"
    exit 1
fi

git log | sed -n '3p' | sed -E 's/Date:   /Last Commit Date: /'
echo "Number of Commits per Author:"
git log --pretty=format:"%aN" | sort | uniq -c | sort -r -k1,1nr