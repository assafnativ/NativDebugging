import urllib2
import datetime
import threading
import time

def downloadBinaryFromSymbolsServer( filename, date_time, file_size ):
    if isinstance(date_time, str):
        # Minuts Hours DayOfTheMonth Month Year
        date_time = int(time.mktime(time.strptime(date_time, '%M %H %d %m %Y')))
    elif not isinstance(date_time, (int, long)):
        date_time = int(time.mktime(date_time))
    url  = "http://msdl.microsoft.com/download/symbols/"
    url += filename
    url += "/"
    url += "%X" % date_time
    url += "%X" % file_size
    url += "/"
    url += filename[:-1] + '_'
    req = urllib2.Request(url=url)
    req.add_header("Accept-Encoding", "gzip")
    req.add_header("User-Agent", "Microsoft-Symbol-Server/6.2.9200.16384")
    req.add_header("Host", "msdl.microsoft.com")
    req.add_header("Connection", "Keep-Alive")
    req.add_header("Cache-Control", "no-cache")
    try:
        res = urllib2.urlopen(req)
    except urllib2.HTTPError, e:
        if 404 == e.getcode():
            return
    data = res.read()
    res.close()
    return data

def normalizeDate(date):
    if isinstance(date, tuple):
        date = int(time.mktime((date[0], date[1], date[2], 0, 0, 0, 0, 0, 0)))
    elif isinstance(date, (int, long)):
        pass
    elif isinstance(date, None):
        date = int(time.mktime(time.strptime(end.ctime())))
    else:
        raise Exception("Don't know how to translate the date to int")
    return date

def _setStartAndEndDate(date):
    # Make the end time/date the begging of the next day
    start = normalizeDate(date)
    start_date = datetime.date.fromtimestamp(start)
    end = start_date + datetime.timedelta(days=1)
    end = int(time.mktime(time.strptime(end.ctime())))
    if end <= start:
        raise Exception("Faild to caculate the end date %x" % end)
    return (start, end)

def bruteForceDateTimeDownload(filename, date, file_size, is_verbose=True):
    start, end = _setStartAndEndDate(date)
    function_timing = time.time()
    if is_verbose:
        print "Starting from timestamp %x" % start
        print "Would end on timestamp  %x" % end
    for date_time in range(start, end):
        try:
            r = downloadBinaryFromSymbolsServer(filename, date_time, file_size)
            if None != r:
                print hex(date_time)
                return r
            attempts = 0
            if is_verbose and date_time == (date_time & 0xfffffff0):
                running_time = time.time() - function_timing
                number_of_execuations = date_time - start
                avg = float(number_of_execuations) / running_time
                if 0 != avg:
                    left = end - date_time
                    left_sec = float(left) / avg
                    print "Last attempt:", hex(date_time), "Secs passed:", int(running_time), "Avg of", avg, "quries/sec. ~%f secs left" % left_sec
        except Exception, e:
            print e
            attempts += 1
            if attempts > 3:
                raise e
            time.sleep(2)

class CreateBruteForceThread(threading.Thread):
    def __init__(self, filename, start, end, file_size, is_verbose=True):
        self.filename = filename
        self.start = start
        self.end = end
        self.file_size = file_size
        self.is_verbose = is_verbose
        self.result = None
        threading.Thread.__init__(self)
    def run(self):
        self.result = bruteForceDateTimeDownload(self.filename, self.start, self.file_size, self.end)

# Fix this shit
def runMuntiThreadBruteForce(filename, start, file_size, num_threads=10, is_verbose=True):
    start, end = _setStartAndEndDate(date)
    last_start = start
    thread_range = 0x1000
    running_threads = []
    result = None
    while None == result:
        if len(running_threads) < num_threads:
            t = CreateBruteForceThread(filename, last_start, last_start + thread_range, file_size, is_verbose)
            running_threads.append(t)
            last_start += thread_range

