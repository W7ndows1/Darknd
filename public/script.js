(function () {
    const mod = (n, m) => ((n % m) + m) % m;
    const baseDictionary = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~-';
    const shuffledIndicator = '_rhs';
    const generateDictionary = function () {
        let str = '';
        const split = baseDictionary.split('');
        while (split.length > 0) {
            str += split.splice(Math.floor(Math.random() * split.length), 1)[0];
        }
        return str;
    };
    class StrShuffler {
        constructor(dictionary = generateDictionary()) {
            this.dictionary = dictionary;
        }
        shuffle(str) {
            if (str.startsWith(shuffledIndicator)) {
                return str;
            }
            let shuffledStr = '';
            for (let i = 0; i < str.length; i++) {
                const char = str.charAt(i);
                const idx = baseDictionary.indexOf(char);
                if (char === '%' && str.length - i >= 3) {
                    shuffledStr += char;
                    shuffledStr += str.charAt(++i);
                    shuffledStr += str.charAt(++i);
                } else if (idx === -1) {
                    shuffledStr += char;
                } else {
                    shuffledStr += this.dictionary.charAt(mod(idx + i, baseDictionary.length));
                }
            }
            return shuffledIndicator + shuffledStr;
        }
        unshuffle(str) {
            if (!str.startsWith(shuffledIndicator)) {
                return str;
            }
            str = str.slice(shuffledIndicator.length);
            let unshuffledStr = '';
            for (let i = 0; i < str.length; i++) {
                const char = str.charAt(i);
                const idx = this.dictionary.indexOf(char);
                if (char === '%' && str.length - i >= 3) {
                    unshuffledStr += char;
                    unshuffledStr += str.charAt(++i);
                    unshuffledStr += str.charAt(++i);
                } else if (idx === -1) {
                    unshuffledStr += char;
                } else {
                    unshuffledStr += baseDictionary.charAt(mod(idx - i, baseDictionary.length));
                }
            }
            return unshuffledStr;
        }
    }

    function setError(err) {
        var element = document.getElementById('error-text');
        if (!element) return;
        if (err) {
            element.style.display = 'block';
            element.textContent = 'An error occurred: ' + err;
        } else {
            element.style.display = 'none';
            element.textContent = '';
        }
    }
    function getPassword() {
        var element = document.getElementById('session-password');
        return element ? element.value : '';
    }
    function get(url, callback, shush = false) {
        var pwd = getPassword();
        if (pwd) {
            if (url.includes('?')) {
                url += '&pwd=' + pwd;
            } else {
                url += '?pwd=' + pwd;
            }
        }
        var request = new XMLHttpRequest();
        request.open('GET', url, true);
        request.send();
        request.onerror = function () {
            if (!shush) setError('Cannot communicate with the server');
        };
        request.onload = function () {
            if (request.status === 200) {
                callback(request.responseText);
            } else {
                if (!shush)
                    setError(
                        'unexpected server response to not match "200". Server says "' + request.responseText + '"'
                    );
            }
        };
    }

    var api = {
        needpassword(callback) {
            get('/needpassword', value => callback(value === 'true'));
        },
        newsession(callback) {
            get('/newsession', callback);
        },
        editsession(id, httpProxy, enableShuffling, callback) {
            get(
                '/editsession?id=' +
                encodeURIComponent(id) +
                (httpProxy ? '&httpProxy=' + encodeURIComponent(httpProxy) : '') +
                '&enableShuffling=' + (enableShuffling ? '1' : '0'),
                function (res) {
                    if (res !== 'Success') return setError('unexpected response from server. received ' + res);
                    callback();
                }
            );
        },
        sessionexists(id, callback) {
            get('/sessionexists?id=' + encodeURIComponent(id), function (res) {
                if (res === 'exists') return callback(true);
                if (res === 'not found') return callback(false);
                setError('unexpected response from server. received' + res);
            });
        },
        deletesession(id, callback) {
            api.sessionexists(id, function (exists) {
                if (exists) {
                    get('/deletesession?id=' + id, function (res) {
                        if (res !== 'Success' && res !== 'not found')
                            return setError('unexpected response from server. received ' + res);
                        callback();
                    });
                } else {
                    callback();
                }
            });
        },
        shuffleDict(id, callback) {
            get('/api/shuffleDict?id=' + encodeURIComponent(id), function (res) {
                callback(JSON.parse(res));
            });
        }
    };

    var localStorageKey = 'rammerhead_sessionids';
    var localStorageKeyDefault = 'rammerhead_default_sessionid';
    var sessionIdsStore = {
        get() {
            var rawData = localStorage.getItem(localStorageKey);
            if (!rawData) return [];
            try {
                var data = JSON.parse(rawData);
                if (!Array.isArray(data)) throw 'getout';
                return data;
            } catch (e) {
                return [];
            }
        },
        set(data) {
            if (!data || !Array.isArray(data)) throw new TypeError('must be array');
            localStorage.setItem(localStorageKey, JSON.stringify(data));
        },
        getDefault() {
            var sessionId = localStorage.getItem(localStorageKeyDefault);
            if (sessionId) {
                var data = sessionIdsStore.get();
                data.filter(function (e) {
                    return e.id === sessionId;
                });
                if (data.length) return data[0];
            }
            return null;
        },
        setDefault(id) {
            localStorage.setItem(localStorageKeyDefault, id);
        }
    };

    get('/mainport', function (data) {
        var defaultPort = window.location.protocol === 'https:' ? 443 : 80;
        var currentPort = window.location.port || defaultPort;
        var mainPort = data || defaultPort;
        if (currentPort != mainPort) window.location.port = mainPort;
    });

    api.needpassword(doNeed => {
        if (doNeed) {
            var el = document.getElementById('password-wrapper');
            if (el) el.style.display = '';
        }
    });

    window.addEventListener('load', function () {
        // ── KEY GATE ──────────────────────────────────────────
        const VALID_KEYS = [
            'adminhalt',
            'admineye'
        ];
        const STORAGE_KEY = 'rh_access_key';

        const loginOverlay = document.getElementById('login-overlay');
        const homeUI = document.getElementById('home-ui');

        function showHome() {
            if (loginOverlay) loginOverlay.style.display = 'none';
            if (homeUI) homeUI.style.display = 'flex';
            initProxy();
        }

        function validateKey() {
            const input = document.getElementById('keyInput');
            const errorMsg = document.getElementById('errorMsg');
            const card = document.getElementById('loginCard');
            const key = input.value.trim();
            if (!key) { showKeyError('Please enter your access key.', card); return; }
            if (VALID_KEYS.includes(key)) {
                sessionStorage.setItem(STORAGE_KEY, key);
                input.disabled = true;
                document.getElementById('submitBtn').disabled = true;
                errorMsg.style.color = '#44ff88';
                errorMsg.textContent = 'ACCESS GRANTED';
                setTimeout(showHome, 600);
            } else {
                showKeyError('Invalid key. Access denied.', card);
                input.value = '';
                input.focus();
            }
        }

        function showKeyError(msg, card) {
            const errorMsg = document.getElementById('errorMsg');
            errorMsg.style.color = '#ff4444';
            errorMsg.textContent = msg;
            card.classList.remove('shake');
            void card.offsetWidth;
            card.classList.add('shake');
        }

        // Check if already authenticated
        const stored = sessionStorage.getItem(STORAGE_KEY);
        if (stored && VALID_KEYS.includes(stored)) {
            showHome();
        } else {
            if (loginOverlay) loginOverlay.style.display = 'flex';
            if (homeUI) homeUI.style.display = 'none';
        }

        // Wire up login UI
        const keyInput = document.getElementById('keyInput');
        if (keyInput) keyInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') validateKey(); });
        const submitBtn = document.getElementById('submitBtn');
        if (submitBtn) submitBtn.addEventListener('click', validateKey);

        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) logoutBtn.addEventListener('click', function() {
            sessionStorage.removeItem(STORAGE_KEY);
            location.reload();
        });

        // ── PROXY INIT ────────────────────────────────────────
        function initProxy() {
            // Auto-create a session on load
            api.newsession(function (id) {
                document.getElementById('session-id').value = id;
            });

            function go() {
                setError();
                var id = document.getElementById('session-id').value;
                var enableShuffling = true;
                var url = document.getElementById('session-url').value || 'https://www.google.com/';

                // Normalize URL
                if (!url.includes('.') || url.includes(' ')) {
                    url = 'https://www.google.com/search?q=' + encodeURIComponent(url);
                } else if (!url.startsWith('http://') && !url.startsWith('https://')) {
                    url = 'https://' + url;
                }

                if (!id) return setError('must generate a session id first');
                api.sessionexists(id, function (value) {
                    if (!value) {
                        // Session gone, create a new one then go
                        api.newsession(function(newId) {
                            document.getElementById('session-id').value = newId;
                            id = newId;
                            proceedToProxy(id, enableShuffling, url);
                        });
                    } else {
                        proceedToProxy(id, enableShuffling, url);
                    }
                });
            }

            function proceedToProxy(id, enableShuffling, url) {
                api.editsession(id, '', enableShuffling, function () {
                    api.shuffleDict(id, function (shuffleDict) {
                        if (!shuffleDict) {
                            window.location.href = '/' + id + '/' + url;
                        } else {
                            var shuffler = new StrShuffler(shuffleDict);
                            window.location.href = '/' + id + '/' + shuffler.shuffle(url);
                        }
                    });
                });
            }

            document.getElementById('session-go').onclick = go;
            document.getElementById('session-url').onkeydown = function (event) {
                if (event.key === 'Enter') go();
            };

            // Focus the URL bar
            setTimeout(function() {
                var urlInput = document.getElementById('session-url');
                if (urlInput) urlInput.focus();
            }, 100);
        }
    });
})();

// Canvas particle background
(function initCanvas() {
  var canvas = document.getElementById('bg');
  if (!canvas) return;
  var ctx = canvas.getContext('2d');
  var W, H, dots = [];
  function resize() { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; }
  function mkDot() { return { x: Math.random()*W, y: Math.random()*H, r: Math.random()*1.2+0.3, a: Math.random(), speed: Math.random()*0.003+0.001, drift: (Math.random()-0.5)*0.15 }; }
  function init() { resize(); dots = Array.from({length:80}, mkDot); }
  function draw() {
    ctx.clearRect(0,0,W,H);
    for (var i=0;i<dots.length;i++) {
      var d=dots[i];
      d.a+=d.speed; if(d.a>1)d.a=0;
      d.x+=d.drift; if(d.x<0)d.x=W; if(d.x>W)d.x=0;
      var alpha=Math.sin(d.a*Math.PI)*0.35;
      ctx.beginPath(); ctx.arc(d.x,d.y,d.r,0,Math.PI*2);
      ctx.fillStyle='rgba(255,255,255,'+alpha+')'; ctx.fill();
    }
    requestAnimationFrame(draw);
  }
  window.addEventListener('resize', resize);
  init(); draw();
})();
