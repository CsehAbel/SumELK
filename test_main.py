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

        print((datetime.datetime.now()-datetime.timedelta(days=90)).strftime("%Y_%m_%d"))

        self.assertEqual(diff_days,90)

    def test_mod(self):
        init_length=23
        length = 23
        oszto=5
        egeszresz=0
        while not (length<oszto):
            length=length-oszto
            egeszresz+=1
        maradek=length

        elozo_also_korlat = 0
        for i in range(egeszresz+1):
            sliced_list = []
            for x in range(init_length):
                if ((elozo_also_korlat <= x) and (x < ((i + 1) * oszto))):
                    sliced_list.append(x)
            elozo_also_korlat = (i+1) * oszto
            print(sliced_list)

        self.assertTrue(maradek==3)

        self.assertTrue(egeszresz == 1)

    def test_mod(self):
        init_length = 23
        length = 23
        lista=[x for x in range(23)]
        oszto = 5
        egeszresz = 0
        egeszresz,maradek = divmod(length,oszto)

        lower_bound = 0
        for i in range(egeszresz+1):
            if (i+1)*oszto<length:
                slice_part=lista[slice(lower_bound,(i+1)*oszto,1)]
            else:
                slice_part = lista[slice(lower_bound,length,1)]
            lower_bound=(i+1)*oszto
            print(slice_part)