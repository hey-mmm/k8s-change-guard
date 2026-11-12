import base64,hashlib,unittest
from unittest.mock import patch
from change_guard.github import GitHubClient,TreeSecurityError

class GitHubBlobTransportTests(unittest.TestCase):
    def test_github_wrapped_base64_is_validated_after_line_unwrap(self):
        raw=b'long rendered chart data\n'*100
        sha=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        response={'encoding':'base64','size':len(raw),'content':base64.encodebytes(raw).decode()}
        client=GitHubClient('owner/repo','fake-test-token')
        with patch.object(client,'get',return_value=response):
            self.assertEqual(client._fetch_blob(sha,len(raw),limit=10000),raw)
        response['content']='!'+response['content']
        client=GitHubClient('owner/repo','fake-test-token')
        with patch.object(client,'get',return_value=response),self.assertRaises(TreeSecurityError):
            client._fetch_blob(sha,len(raw),limit=10000)

if __name__=='__main__':unittest.main()
