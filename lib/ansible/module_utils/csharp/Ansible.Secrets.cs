using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Ansible.Secrets
{
    public class SecretMasker
    {
        private static readonly SecretMasker _instance = new SecretMasker();

        private readonly List<Node> _nodes;
        public readonly HashSet<string> _registered;
        private HashSet<string> _newSecrets;
        private bool _dirty;

        public static SecretMasker Instance
        {
            get
            {
                return _instance;
            }
        }

        public static void _RegisterAnsibleSecrets(IEnumerable<SecureString> secrets)
        {
            // This isn't ideal but we need the plaintext string in memory and the
            // SecureString was only a way to avoid AMSI/PowerShell logging of values
            // rather than trying to protect them in memory.
            SecretMasker masker = SecretMasker.Instance;

            foreach (SecureString secret in secrets)
            {
                if (secret.Length == 0)
                {
                    continue;
                }

                IntPtr stringPtr = IntPtr.Zero;
                try
                {
                    stringPtr = Marshal.SecureStringToBSTR(secret);
                    string secretString = Marshal.PtrToStringBSTR(stringPtr);
                    masker.RegisterSecret(secretString);
                }
                finally
                {
                    if (stringPtr != IntPtr.Zero)
                    {
                        Marshal.ZeroFreeBSTR(stringPtr);
                        stringPtr = IntPtr.Zero;
                    }
                }
            }

            // We want to keep track of new secrets so drain the ones we
            // already know about.
            masker.DrainNewSecrets();
        }

        private SecretMasker()
        {
            _nodes = new List<Node>();
            _registered = new HashSet<string>(StringComparer.Ordinal);
            _newSecrets = new HashSet<string>(StringComparer.Ordinal);
            _dirty = false;
            _nodes.Add(new Node());
        }

        public HashSet<string> DrainNewSecrets()
        {
            HashSet<string> result = _newSecrets;
            _newSecrets = new HashSet<string>(StringComparer.Ordinal);
            return result;
        }

        public void RegisterSecret(string secret)
        {
            if (string.IsNullOrEmpty(secret))
            {
                return;
            }

            if (!_registered.Add(secret))
            {
                return;
            }

            int current = 0;
            for (int i = 0; i < secret.Length; i++)
            {
                char c = secret[i];
                int next;
                if (!_nodes[current].Children.TryGetValue(c, out next))
                {
                    next = _nodes.Count;
                    _nodes.Add(new Node());
                    _nodes[current].Children[c] = next;
                }
                current = next;
            }

            if (_nodes[current].PatternLength == 0)
            {
                _nodes[current].PatternLength = secret.Length;
            }

            _dirty = true;
            _newSecrets.Add(secret);

            return;
        }

        public string MaskString(string value)
        {
            return MaskString(value, "<secret>");
        }

        public string MaskString(string value, string maskPlaceholder)
        {
            if (string.IsNullOrEmpty(value) || _registered.Count == 0)
            {
                return value;
            }

            if (_dirty)
            {
                BuildAutomaton();
                _dirty = false;
            }

            int state = 0;
            int writePos = 0;
            int regionStart = -1;
            int regionEnd = -1;
            StringBuilder sb = null;

            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];

                while (state != 0 && !_nodes[state].Children.ContainsKey(c))
                {
                    state = _nodes[state].FailureLink;
                }

                int next;
                if (_nodes[state].Children.TryGetValue(c, out next))
                {
                    state = next;
                }

                int matchLen = GetLongestMatch(state);
                if (matchLen > 0)
                {
                    int mStart = i - matchLen + 1;
                    int mEnd = i + 1;

                    if (regionStart < 0)
                    {
                        regionStart = mStart;
                        regionEnd = mEnd;
                    }
                    else if (mStart < regionEnd)
                    {
                        if (mEnd > regionEnd)
                        {
                            regionEnd = mEnd;
                        }
                    }
                    else
                    {
                        if (sb == null)
                        {
                            sb = new StringBuilder(value.Length);
                        }
                        sb.Append(value, writePos, regionStart - writePos);
                        sb.Append(maskPlaceholder);
                        writePos = regionEnd;
                        regionStart = mStart;
                        regionEnd = mEnd;
                    }
                }
            }

            if (regionStart < 0)
            {
                return value;
            }

            if (sb == null)
            {
                sb = new StringBuilder(value.Length);
            }
            sb.Append(value, writePos, regionStart - writePos);
            sb.Append(maskPlaceholder);
            writePos = regionEnd;
            sb.Append(value, writePos, value.Length - writePos);

            return sb.ToString();
        }

        private int GetLongestMatch(int state)
        {
            if (state == 0)
            {
                return 0;
            }

            if (_nodes[state].PatternLength > 0)
            {
                return _nodes[state].PatternLength;
            }

            int outLink = _nodes[state].OutputLink;
            if (outLink > 0)
            {
                return _nodes[outLink].PatternLength;
            }

            return 0;
        }

        private void BuildAutomaton()
        {
            for (int i = 0; i < _nodes.Count; i++)
            {
                _nodes[i].FailureLink = 0;
                _nodes[i].OutputLink = 0;
            }

            Queue<int> queue = new Queue<int>();

            foreach (KeyValuePair<char, int> kvp in _nodes[0].Children)
            {
                _nodes[kvp.Value].FailureLink = 0;
                queue.Enqueue(kvp.Value);
            }

            while (queue.Count > 0)
            {
                int current = queue.Dequeue();

                foreach (KeyValuePair<char, int> kvp in _nodes[current].Children)
                {
                    char c = kvp.Key;
                    int child = kvp.Value;
                    queue.Enqueue(child);

                    int f = _nodes[current].FailureLink;
                    while (f != 0 && !_nodes[f].Children.ContainsKey(c))
                    {
                        f = _nodes[f].FailureLink;
                    }

                    int fChild;
                    if (_nodes[f].Children.TryGetValue(c, out fChild) && fChild != child)
                    {
                        _nodes[child].FailureLink = fChild;
                    }
                    else
                    {
                        _nodes[child].FailureLink = 0;
                    }

                    int fl = _nodes[child].FailureLink;
                    if (_nodes[fl].PatternLength > 0)
                    {
                        _nodes[child].OutputLink = fl;
                    }
                    else
                    {
                        _nodes[child].OutputLink = _nodes[fl].OutputLink;
                    }
                }
            }
        }

        private class Node
        {
            public readonly Dictionary<char, int> Children;
            public int FailureLink;
            public int OutputLink;
            public int PatternLength;

            public Node()
            {
                Children = new Dictionary<char, int>();
            }
        }
    }
}
