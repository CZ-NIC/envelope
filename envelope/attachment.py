import logging
from pathlib import Path

from .utils import assure_fetched, get_mimetype

logger = logging.getLogger(__name__)


class Attachment:

    def __init__(self, contents):
        """ get contents, user-defined name, user-defined mimetype and possibly True for being inline
        :type contents: data/Path [,mimetype] [,name] [,True for inline]
        """
        name = mimetype = inline = None
        if type(contents) is tuple:
            for s in contents[1:]:
                if not s:
                    continue
                elif s is True:
                    inline = True
                elif "/" in s:
                    mimetype = s
                else:
                    name = s
            if len(contents) == 4 and contents[3] and not inline:
                # (path, None, None, "cid.jpg") -> whereas name = "cid.jpg", inline is still not defined
                inline = True
            contents = contents[0]
        if not name and isinstance(contents, Path):
            name = contents.name
        if not name:
            name = "attachment.txt"

        try:
            data = assure_fetched(contents, bytes)
        except FileNotFoundError:
            logger.error(f"Could not fetch file {contents.absolute()}")
            raise
        if not mimetype:
            if isinstance(contents, Path):
                mimetype = get_mimetype(path=contents)
            else:
                mimetype = get_mimetype(data=data)

        self.data: bytes = data
        self.mimetype = mimetype
        self.name = name
        self.inline = inline

    def __repr__(self):
        l = [self.name, self.mimetype, self.get_sample()]
        if self.inline:
            l.append("inline=True")
        return f"Attachment({', '.join(l)})"

    def __str__(self):
        return str(self.data, "utf-8")

    def __bytes__(self):
        return self.data

    def get_sample(self):
        if self.data is None:
            raise ValueError(f"Empty attachment {self.name}")
        sample = self.data.decode(
            "utf-8", "ignore").replace("\n", " ").replace("\r", " ")
        if len(sample) > 24:
            sample = sample[:20].strip() + "..."
        return sample

    def preview(self):
        if self.inline:
            return f"{self.name} ({self.mimetype}): <img src='cid:{self.inline}'/>"
        else:
            return f"{self.name} ({self.mimetype}): {self.get_sample()}"
