import datetime
import time
from unittest import TestCase
import main
import re

class TestRegexpMatchRuleName(TestCase):
    def test_regexp_rule_matching(self):
        #rules=["App123","APP123","wuser123","a_123","mas","ofi"]
        resp=main.filteredresults()
        pattern_a=re.compile("!a.*")
        pattern_wuser=re.compile("!wuser.*")
        notfoundkakukk=True
        for hit in resp["hits"]["hits"]:
            hit_rn=hit["_source"]["rule"]["name"]
            if pattern_a.match(hit_rn) or pattern_wuser.match(hit_rn):
                pass
            else:
                notfoundkakukk=False
        self.assertTrue(notfoundkakukk)

    def test_dateadding(self):
        #GET /energy-checkpoint -> ct
        ct=datetime.datetime.fromtimestamp(1635211853772/1000.0)
        difference=datetime.datetime.now()-ct
        diff_days=difference.days
        gt=datetime.datetime(day=27,month=10,year=2021)
        duration=datetime.timedelta(days=30)
        lt=gt+duration
        lt=lt.strftime("%Y_%m_%d")
        self.assertEqual(diff_days,90)
