/* GitAnalyzer dashboard.
 *
 * Runs in two modes from the same source:
 *   live    - served by `gitanalyzer serve`, talks to the local JSON API
 *   static  - exported by `gitanalyzer report`, data embedded in the page
 */
(function () {
  "use strict";

  var LIVE = window.__SCAN__ === null;
  var state = {
    scan: window.__SCAN__,
    scans: [],
    selectedId: null,
    openAccounts: {},
    openRepos: {},
    hiddenAccounts: {},
    hiddenRepos: {},
    categories: {},   // empty = show every category
    timer: null,
    settings: null,
    providers: [],
    status: null,
    patterns: null,
    view: "scans",
    dirty: false,
    ui: {},
  };

  var TYPE_LABELS = {
    aws_key: "AWS key", github_token: "GitHub token", api_key: "API key",
    private_key: "Private key", jwt: "JWT", db_credential: "DB credential",
    hardcoded_secret: "Hardcoded secret", cloud_credential: "Cloud credential",
    package_token: "Package token", payment_key: "Payment key",
    credential_url: "Credential URL", ai_api_key: "AI API key", ml_key: "ML key",
    blockchain_key: "Blockchain key", search_key: "Search key", bot_token: "Bot token",
    webhook: "Webhook", low_value_key: "Low-value key", slack: "Slack",
    google_docs: "Google Docs", jira: "Jira", notion: "Notion", okta: "Okta",
    auth0: "Auth0", sharepoint: "SharePoint", internal_url: "Internal URL",
    dashboard: "Dashboard", ci_cd: "CI/CD", sentry: "Sentry", firebase: "Firebase",
    url: "URL", other: "Other",
  };
  // Pill colour by what the finding actually is, so a wall of rows still
  // reads at a glance: credentials warm, infrastructure cool, noise grey.
  var TYPE_CLASS = {
    api_key: "cred", private_key: "cred", hardcoded_secret: "cred",
    db_credential: "cred", credential_url: "cred", payment_key: "cred",
    bot_token: "cred", ai_api_key: "cred", ml_key: "cred", search_key: "cred",
    blockchain_key: "cred", package_token: "cred", github_token: "cred",
    low_value_key: "other",
    aws_key: "cloud", cloud_credential: "cloud", firebase: "cloud",
    okta: "id", auth0: "id", jwt: "id",
    google_docs: "doc", sharepoint: "doc", notion: "doc",
    slack: "saas", jira: "saas", sentry: "saas", webhook: "saas",
    internal_url: "infra", dashboard: "infra", ci_cd: "infra",
    url: "url", other: "other",
  };

  var AI_LABELS = {
    true_positive: "AI: confirmed",
    false_positive: "AI: dismissed",
    needs_review: "AI: review",
  };

  // ---------- helpers ----------
  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function typeLabel(t) { return TYPE_LABELS[t] || t || "other"; }
  // The scan dialog is built from a string; values interpolated into it
  // are user-controlled (keywords, model ids), so they get escaped.
  function attr(value) {
    return String(value === undefined || value === null ? "" : value)
      .replace(/&/g, "&amp;").replace(/"/g, "&quot;")
      .replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  function typeClass(t) { return "ty-" + (TYPE_CLASS[t] || "other"); }

  var URL_RE = /https?:\/\/[^\s"'<>)\]]+/gi;
  function extractUrls(text) {
    var found = String(text || "").match(URL_RE) || [];
    var seen = {}, out = [];
    found.forEach(function (u) {
      var clean = u.replace(/[.,;]+$/, "");
      if (!seen[clean]) { seen[clean] = 1; out.push(clean); }
    });
    return out;
  }
  function fmtDate(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d)) return iso;
    return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  }
  function debounce(fn, ms) {
    var t;
    return function () {
      var args = arguments;
      clearTimeout(t);
      t = setTimeout(function () { fn.apply(null, args); }, ms);
    };
  }
  function api(path, options) {
    return fetch(path, options).then(function (r) {
      if (r.ok) return r.json();
      // The server explains itself in the body; surfacing only the status
      // code turns every distinct failure into the same useless "HTTP 502".
      return r.json().catch(function () { return null; }).then(function (body) {
        throw new Error((body && body.error) || "HTTP " + r.status);
      });
    });
  }

  // ---------- filtering ----------
  function filters() {
    return {
      q: $("q").value.trim().toLowerCase(),
      noise: $("f-noise").checked,
      severity: $("f-severity").value,
      scanner: $("f-scanner").value,
      account: $("f-account").value,
      type: $("f-type").value,
      ai: $("f-ai").value,
      verified: $("f-verified").checked,
    };
  }

  function visibleFindings() {
    if (!state.scan || !state.scan.findings) return [];
    var f = filters();
    var seen = {};
    return state.scan.findings.filter(function (item) {
      var key = item.repo + ":" + item.file + ":" + item.line + ":" + item.pattern;
      if (seen[key]) return false;
      seen[key] = 1;

      if (state.hiddenAccounts[item.account]) return false;
      if (state.hiddenRepos[item.repo]) return false;
      if (f.verified && !item.verified) return false;
      if (f.severity !== "all" && item.severity !== f.severity) return false;
      if (f.scanner !== "all" && item.scanner !== f.scanner) return false;
      if (f.account !== "all" && item.account !== f.account) return false;
      if (f.type !== "all" && (item.finding_type || "other") !== f.type) return false;
      if (f.ai !== "all" && (item.ai_verdict || "") !== f.ai) return false;

      // Everything shows unless you ask for less: no selected chip means no
      // category filter, and the noise toggle is opt-in.
      var cat = item.category || "other";
      var picked = Object.keys(state.categories);
      if (picked.length && !state.categories[cat]) return false;
      if (f.noise) {
        if (cat === "all_url") return false;
        if (item.severity === "informative") return false;
        if (item.ai_verdict === "false_positive" && (item.ai_confidence || 0) >= 70) return false;
      }

      if (f.q) {
        var hay = (item.repo + " " + item.file + " " + item.pattern + " " + item.preview).toLowerCase();
        if (hay.indexOf(f.q) === -1) return false;
      }
      return true;
    });
  }

  function groupByAccount(findings) {
    var accounts = {};
    findings.forEach(function (item) {
      var a = accounts[item.account] || (accounts[item.account] = {});
      (a[item.repo] || (a[item.repo] = [])).push(item);
    });
    return Object.keys(accounts).map(function (account) {
      var repos = Object.keys(accounts[account]).map(function (repo) {
        var items = accounts[account][repo].sort(function (x, y) { return y.score - x.score; });
        return {
          repo: repo,
          url: items[0].repo_url,
          items: items,
          max: Math.max.apply(null, items.map(function (i) { return i.score; })),
        };
      }).sort(function (x, y) { return y.max - x.max; });
      var all = repos.reduce(function (acc, r) { return acc + r.items.length; }, 0);
      return {
        account: account,
        repos: repos,
        total: all,
        verified: repos.reduce(function (acc, r) {
          return acc + r.items.filter(function (i) { return i.verified; }).length;
        }, 0),
        max: Math.max.apply(null, repos.map(function (r) { return r.max; })),
      };
    }).sort(function (x, y) { return y.max - x.max; });
  }

  // ---------- rendering ----------
  function card(value, label, sub, cls) {
    var node = el("div", "card" + (cls ? " " + cls : ""));
    node.appendChild(el("div", "n", value));
    node.appendChild(el("div", "k", label));
    if (sub) node.appendChild(el("div", "sub", sub));
    return node;
  }

  function renderSummary() {
    var box = $("summary");
    var bar = $("breakdown");
    box.innerHTML = "";
    bar.innerHTML = "";
    if (!state.scan) return;

    var stats = state.scan.stats || {};
    var all = state.scan.findings || [];
    var shown = visibleFindings().length;
    var counts = { critical: 0, high: 0, medium: 0, low: 0, informative: 0 };
    var verified = 0;
    all.forEach(function (f) {
      if (counts[f.severity] !== undefined) counts[f.severity]++;
      if (f.verified) verified++;
    });

    var skipped = (state.scan.skipped_accounts || []).length;
    box.appendChild(card(stats.accounts_scanned || 0, "accounts scanned",
      skipped ? skipped + " skipped" : ""));
    box.appendChild(card(stats.repos_scanned || 0, "repos scanned",
      stats.repos_skipped ? stats.repos_skipped + " filtered out" : ""));
    box.appendChild(card(shown, "findings shown",
      all.length !== shown ? all.length + " before filters" : ""));

    // Severity at a glance. A scan with criticals must not look like a clean one.
    var sev = el("div", "card" + (counts.critical ? " alert" : ""));
    var pills = el("div", "sevs");
    ["critical", "high", "medium", "low", "informative"].forEach(function (name) {
      if (!counts[name]) return;
      // "I" for informative — it is the one band that is not a severity.
      pills.appendChild(el("span", "sev-pill sev-" + name,
        counts[name] + (name === "informative" ? "I" : name.charAt(0).toUpperCase())));
    });
    if (!pills.childNodes.length) pills.appendChild(el("span", "sub", "nothing scored"));
    sev.appendChild(pills);
    sev.appendChild(el("div", "k", "by severity"));
    box.appendChild(sev);

    box.appendChild(card(verified, "live verified",
      verified ? "confirmed working" : "none confirmed",
      verified ? "alert" : "clean"));

    // Which scanner produced what — the two do different jobs.
    function part(cls, label, value) {
      var node = el("span", cls);
      node.appendChild(el("b", null, label));
      node.appendChild(document.createTextNode(" " + value));
      return node;
    }
    bar.appendChild(part("th", "TruffleHog", stats.trufflehog_findings || 0));
    if (verified) bar.appendChild(part("vf", "verified", verified));
    bar.appendChild(part("rg", "ripgrep", stats.ripgrep_findings || 0));
    if (stats.clone_failures) {
      bar.appendChild(part("", "clone failures", stats.clone_failures));
    }
    if (stats.keyword_matches) {
      bar.appendChild(part("", "keyword hits", stats.keyword_matches));
    }
  }

  function renderStats() {
    var box = $("stats");
    box.innerHTML = "";
    if (!state.scan) return;
    var s = state.scan.stats || {};
    var shown = visibleFindings().length;
    var crit = (state.scan.findings || []).filter(function (f) { return f.severity === "critical"; }).length;
    var rows = [["findings", shown, ""]];
    if (crit) rows.push(["critical", crit, "crit"]);
    if (s.verified_secrets) rows.push(["verified", s.verified_secrets, "verified"]);
    rows.forEach(function (r) {
      var stat = el("div", "stat" + (r[2] ? " " + r[2] : ""));
      stat.appendChild(el("b", null, r[1]));
      stat.appendChild(el("span", null, r[0]));
      box.appendChild(stat);
    });
    if (state.scan.status === "running") {
      var live = el("div", "stat");
      live.appendChild(el("span", "running-dot"));
      live.appendChild(el("span", null, "scanning"));
      box.appendChild(live);
    }
  }

  function renderChips() {
    var box = $("chips");
    box.innerHTML = "";
    if (!state.scan) return;

    // Counted from the findings themselves, so the row is right even for a
    // scan written before `stats.categories` existed.
    var counts = {};
    (state.scan.findings || []).forEach(function (item) {
      var key = item.category || "other";
      counts[key] = (counts[key] || 0) + 1;
    });

    var order = ["secret", "company_match", "interesting_url", "other", "all_url"];
    var names = {
      secret: "secrets", company_match: "keyword matches",
      interesting_url: "infrastructure", other: "other", all_url: "plain URLs",
    };
    var picked = Object.keys(state.categories);

    order.forEach(function (key) {
      if (!counts[key]) return;
      var on = !!state.categories[key];
      var chip = el("button", "chip" + (on ? " on" : ""), names[key] + " " + counts[key]);
      chip.title = on ? "Showing only the selected categories — click to remove"
                      : "Click to show only this category";
      chip.onclick = function (e) {
        // Plain click selects just this one; ctrl/cmd or shift adds to the
        // selection, the way a file list behaves.
        if (e.metaKey || e.ctrlKey || e.shiftKey) {
          if (on) delete state.categories[key];
          else state.categories[key] = 1;
        } else if (on && picked.length === 1) {
          state.categories = {};          // clicking the only active one clears
        } else {
          state.categories = {};
          state.categories[key] = 1;
        }
        render();
      };
      box.appendChild(chip);
    });

    if (picked.length) {
      var all = el("button", "chip clear", "show all");
      all.onclick = function () { state.categories = {}; render(); };
      box.appendChild(all);
    }

    var skipped = (state.scan.skipped_accounts || []).length;
    if (skipped) {
      var chip = el("button", "chip", skipped + " accounts skipped");
      chip.title = (state.scan.skipped_accounts || [])
        .map(function (s) { return s.account + " — " + s.reason + (s.detail ? " (" + s.detail + ")" : ""); })
        .join("\n");
      box.appendChild(chip);
    }

    var hidden = Object.keys(state.hiddenAccounts).length + Object.keys(state.hiddenRepos).length;
    if (hidden) {
      var restore = el("button", "chip on", "restore " + hidden + " hidden");
      restore.onclick = function () {
        state.hiddenAccounts = {};
        state.hiddenRepos = {};
        render();
      };
      box.appendChild(restore);
    }
  }

  function renderFilterOptions() {
    if (!state.scan) return;
    var findings = state.scan.findings || [];
    function fill(select, values, labelFn) {
      var current = select.value;
      while (select.options.length > 1) select.remove(1);
      values.forEach(function (v) {
        var opt = document.createElement("option");
        opt.value = v;
        opt.textContent = labelFn ? labelFn(v) : v;
        select.appendChild(opt);
      });
      select.value = Array.prototype.some.call(select.options, function (o) { return o.value === current; })
        ? current : (select.options[0] ? select.options[0].value : "all");
    }
    var accounts = {}, types = {};
    var hasAi = false;
    findings.forEach(function (f) {
      accounts[f.account] = (accounts[f.account] || 0) + 1;
      types[f.finding_type || "other"] = (types[f.finding_type || "other"] || 0) + 1;
      if (f.ai_verdict) hasAi = true;
    });
    fill($("f-account"), Object.keys(accounts).sort(function (a, b) { return accounts[b] - accounts[a]; }));
    fill($("f-type"), Object.keys(types).sort(function (a, b) { return types[b] - types[a]; }), typeLabel);
    $("f-ai").hidden = !hasAi;
  }

  function highlight(text, needle) {
    var wrap = el("div", "line");
    wrap.title = text;
    // Marking the whole line marks nothing. Highlight only when the match is a
    // genuine fragment of the excerpt around it.
    if (!needle || needle.length >= text.length * 0.7) {
      wrap.textContent = text;
      return wrap;
    }
    var low = text.toLowerCase(), target = needle.toLowerCase(), at = 0, index;
    while ((index = low.indexOf(target, at)) !== -1 && target) {
      wrap.appendChild(document.createTextNode(text.slice(at, index)));
      wrap.appendChild(el("mark", null, text.slice(index, index + target.length)));
      at = index + target.length;
      if (wrap.childNodes.length > 40) break;
    }
    wrap.appendChild(document.createTextNode(text.slice(at)));
    return wrap;
  }

  // Leaving the page is a deliberate act, so it gets its own target: tapping
  // a name expands it in place, tapping the arrow opens GitHub.
  function outLink(href, title) {
    var link = el("a", "out", "\u2197");
    link.href = href;
    link.target = "_blank";
    link.rel = "noreferrer noopener";
    link.title = title;
    link.onclick = function (e) { e.stopPropagation(); };
    return link;
  }

  // Collapsed groups still have to show whether something bad is inside.
  function severityDots(items) {
    var dots = el("span", "dots");
    ["critical", "high", "medium"].forEach(function (name) {
      var hit = items.some(function (i) { return i.severity === name; });
      if (hit) dots.appendChild(el("span", "dot " + name));
    });
    return dots;
  }

  function headerRow() {
    var head = el("div", "frow hdr");
    ["score", "sev", "src", "type", "file:line", "finding", ""].forEach(function (label) {
      head.appendChild(el("span", null, label));
    });
    return head;
  }

  function findingNode(item) {
    var row = el("div", "frow r-" + (item.severity || "low"));

    var score = el("span", "sc", item.score);
    if (item.heuristic_score !== undefined && item.heuristic_score !== item.score) {
      // The model moved this one. Say so, and say from where.
      score.classList.add("moved");
      score.title = "heuristic scored " + item.heuristic_score +
        " (" + item.heuristic_severity + "); AI moved it to " + item.score;
    }
    row.appendChild(score);
    var sev = el("span");
    // "informative" does not fit the column and does not need to: the word
    // is in the filter, the badge only has to be unmistakable.
    var sevBadge = el("span", "badge sev-" + item.severity,
      item.severity === "informative" ? "info" : item.severity);
    sevBadge.title = item.severity;
    sev.appendChild(sevBadge);
    row.appendChild(sev);

    // Which scanner found it, and whether the provider confirmed it is live.
    var src = el("span", "src " + (item.scanner === "trufflehog" ? "th" : "rg"),
      (item.scanner === "trufflehog" ? "TH" : "RG") + (item.verified ? " \u2713" : ""));
    src.title = (item.scanner || "scanner") + (item.verified ? " — live verified" : "") +
      (item.detector ? " — " + item.detector : "");
    row.appendChild(src);

    var type = el("span");
    var pill = el("span", "badge ty " + typeClass(item.finding_type), typeLabel(item.finding_type));
    pill.title = typeLabel(item.finding_type);
    type.appendChild(pill);
    row.appendChild(type);

    var loc = el("span", "loc");
    var link = el("a", null, item.file + (item.line ? ":" + item.line : ""));
    link.href = item.repo_url + "/blob/HEAD/" + (item.file || "").replace(/^\/+/, "") +
      (item.line ? "#L" + item.line : "");
    link.target = "_blank";
    link.rel = "noreferrer noopener";
    link.title = item.file + (item.line ? ":" + item.line : "") +
      (item.commit ? " @" + item.commit : "");
    loc.appendChild(link);
    row.appendChild(loc);

    var val = el("div", "val");
    var text = item.preview || item.pattern || "";
    var urls = extractUrls(text);
    if (urls.length) {
      // A link is the finding — make it clickable instead of making it prose.
      urls.slice(0, 3).forEach(function (href) {
        var line = el("div", "urlrow");
        var anchor = el("a", null, href);
        anchor.href = href;
        anchor.target = "_blank";
        anchor.rel = "noreferrer noopener";
        anchor.title = href;
        line.appendChild(anchor);
        val.appendChild(line);
      });
      if (urls.length > 3) val.appendChild(el("div", "rest", "+" + (urls.length - 3) + " more"));
      var rest = text.replace(URL_RE, "").trim();
      if (rest) val.appendChild(el("div", "rest", rest));
    } else {
      val.appendChild(highlight(text, item.pattern));
    }

    var tags = el("div", "tags");
    (item.matched_keywords || []).forEach(function (kw) {
      tags.appendChild(el("span", "badge kw", kw));
    });
    if (item.ai_verdict) {
      tags.appendChild(el("span", "badge ai-" + item.ai_verdict,
        AI_LABELS[item.ai_verdict] + (item.ai_confidence ? " " + item.ai_confidence + "%" : "")));
    }
    if (tags.childNodes.length) val.appendChild(tags);
    if (item.ai_reason) {
      var moved = item.heuristic_score !== undefined && item.heuristic_score !== item.score
        ? item.heuristic_score + " \u2192 " + item.score + " · "
        : "";
      val.appendChild(el("div", "ai-reason", moved + item.ai_reason));
    }
    row.appendChild(val);

    var copy = el("button", "copy", "\u29c9");
    copy.title = "Copy this finding";
    copy.onclick = function (e) {
      e.stopPropagation();
      navigator.clipboard.writeText(
        item.repo + " " + item.file + ":" + item.line + "\n" + item.preview
      ).then(function () {
        copy.textContent = "\u2713";
        setTimeout(function () { copy.textContent = "\u29c9"; }, 1200);
      });
    };
    row.appendChild(copy);
    return row;
  }

  function renderResults() {
    var box = $("results");
    box.innerHTML = "";
    if (!state.scan) {
      box.appendChild(el("div", "empty", "No scan selected."));
      return;
    }
    var findings = visibleFindings();
    if (!findings.length) {
      var empty = el("div", "empty");
      empty.textContent = (state.scan.findings || []).length
        ? "No findings match these filters."
        : (state.scan.status === "running" ? "Scanning — results appear as repos finish." : "No findings.");
      box.appendChild(empty);
      return;
    }

    groupByAccount(findings).forEach(function (group) {
      var groupItems = group.repos.reduce(function (acc, r) { return acc.concat(r.items); }, []);
      var hasCritical = groupItems.some(function (i) { return i.severity === "critical"; });
      var section = el("div", "account" + (hasCritical ? " has-critical" : ""));
      var head = el("div", "head");
      var caret = el("span", "caret" + (state.openAccounts[group.account] ? " open" : ""), "▶");
      head.appendChild(caret);

      head.appendChild(el("span", "name", group.account));
      head.appendChild(outLink("https://github.com/" + group.account,
        "Open " + group.account + " on GitHub"));

      head.appendChild(severityDots(groupItems));
      if (group.verified) head.appendChild(el("span", "badge verified", group.verified + " verified"));
      var spacer = el("span", "spacer");
      head.appendChild(spacer);
      head.appendChild(el("span", "count", group.repos.length + " repos · " + group.total + " findings"));
      var hide = el("button", "ghost", "hide");
      hide.title = "Hide this account from the view";
      hide.onclick = function (e) {
        e.stopPropagation();
        state.hiddenAccounts[group.account] = 1;
        render();
      };
      head.appendChild(hide);

      head.onclick = function () {
        var opening = !state.openAccounts[group.account];
        state.openAccounts[group.account] = opening;
        // Opening an account shows its results. Making you click every repo
        // as well is a second step for no information.
        if (opening) {
          group.repos.forEach(function (r) {
            state.openRepos[group.account + "/" + r.repo] = true;
          });
        }
        render();
      };
      section.appendChild(head);

      if (state.openAccounts[group.account]) {
        group.repos.forEach(function (repo) {
          var repoKey = group.account + "/" + repo.repo;
          var repoNode = el("div", "repo");
          var repoHead = el("div", "head");
          repoHead.appendChild(el("span", "caret" + (state.openRepos[repoKey] ? " open" : ""), "▶"));

          repoHead.appendChild(el("span", "name", repo.repo));
          repoHead.appendChild(outLink(repo.url, "Open " + repo.repo + " on GitHub"));

          repoHead.appendChild(severityDots(repo.items));
          if (repo.items.some(function (i) { return i.verified; })) {
            repoHead.appendChild(el("span", "tick", "\u2713"));
          }
          repoHead.appendChild(el("span", "spacer"));
          repoHead.appendChild(el("span", "count", repo.items.length + " · max " + repo.max));
          var hideRepo = el("button", "ghost", "hide");
          hideRepo.onclick = function (e) {
            e.stopPropagation();
            state.hiddenRepos[repo.repo] = 1;
            render();
          };
          repoHead.appendChild(hideRepo);
          repoHead.onclick = function () {
            state.openRepos[repoKey] = !state.openRepos[repoKey];
            render();
          };
          repoNode.appendChild(repoHead);

          if (state.openRepos[repoKey]) {
            repoNode.appendChild(headerRow());
            repo.items.forEach(function (item) { repoNode.appendChild(findingNode(item)); });
          }
          section.appendChild(repoNode);
        });
      }
      box.appendChild(section);
    });
  }

  function renderLog() {
    var panel = $("log-panel");
    if (!state.scan || !state.scan.log || !state.scan.log.length) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    $("log").textContent = state.scan.log.join("\n");
  }

  function renderSidebar() {
    if (!LIVE) return;
    var box = $("scan-list");
    box.innerHTML = "";
    state.scans.forEach(function (scan) {
      // A wrapper, not one button: the delete control is a button of its own,
      // and a button inside a button is neither valid nor clickable.
      var item = el("div", "scan-item" + (scan.id === state.selectedId ? " active" : ""));
      var open = el("button", "scan-open");
      var row = el("div", "row");
      var left = el("span", null, scan.label || scan.id.slice(0, 15));
      row.appendChild(left);
      if (scan.status === "running") row.appendChild(el("span", "running-dot"));
      else row.appendChild(el("span", "count", (scan.stats || {}).total_findings || 0));
      open.appendChild(row);
      open.appendChild(el("div", "accounts", (scan.accounts || []).join(", ") || "—"));
      open.appendChild(el("div", "meta", fmtDate(scan.started_at) + " · " + scan.status));
      open.onclick = function () { selectScan(scan.id); };
      item.appendChild(open);

      var del = el("button", "scan-del", "\u00d7");
      del.type = "button";
      del.title = "Delete this scan";
      del.setAttribute("aria-label", "Delete the scan of " +
        ((scan.accounts || []).join(", ") || scan.id));
      del.onclick = function (e) {
        e.stopPropagation();
        deleteScan(scan);
      };
      item.appendChild(del);
      box.appendChild(item);
    });
    if (!state.scans.length) {
      box.appendChild(el("div", "empty", "No scans yet."));
    }
  }

  // Deleting the last scan leaves nothing to export. Rather than let the two
  // export buttons fail on an empty view, they go dim with it.
  function syncActions() {
    ["export-md", "export-html"].forEach(function (id) {
      var button = $(id);
      if (button) button.disabled = !state.scan;
    });
  }

  function render() {
    syncActions();
    renderFilterOptions();
    renderSummary();
    renderStats();
    renderChips();
    renderResults();
    renderLog();
    renderSidebar();
  }

  // ---------- export ----------
  function toMarkdown() {
    var findings = visibleFindings();
    var s = (state.scan && state.scan.stats) || {};
    var lines = [
      "# 0xGitAnalyzer report",
      "",
      "- Scan: `" + (state.scan.id || "") + "`",
      "- Accounts scanned: " + (s.accounts_scanned || 0),
      "- Repos scanned: " + (s.repos_scanned || 0),
      "- Findings shown: " + findings.length + " of " + (s.total_findings || 0),
      "- Live-verified secrets: " + (s.verified_secrets || 0),
      "",
    ];
    groupByAccount(findings).forEach(function (group) {
      lines.push("## " + group.account + " (" + group.total + " findings)", "");
      group.repos.forEach(function (repo) {
        lines.push("### " + repo.repo, "");
        repo.items.forEach(function (item) {
          lines.push("- **[" + item.severity.toUpperCase() + " " + item.score + "]** `" +
            item.file + ":" + item.line + "` — " + typeLabel(item.finding_type) +
            (item.verified ? " (live verified)" : ""));
          lines.push("  - scanner: " + item.scanner + (item.detector ? " / " + item.detector : ""));
          if (item.ai_verdict) lines.push("  - ai: " + item.ai_verdict + " — " + (item.ai_reason || ""));
          lines.push("  - `" + (item.preview || "").replace(/`/g, "'").slice(0, 240) + "`");
          lines.push("  - " + repo.url);
        });
        lines.push("");
      });
    });
    return lines.join("\n");
  }

  function download(name, text, mime) {
    var blob = new Blob([text], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }

  // ---------- modals ----------
  // These dialogs hold a half-finished form — a token being typed, a prompt
  // being edited. Clicking the backdrop does NOT close them: losing that to a
  // stray click is far worse than one extra click on Close. Escape still works.
  function mountModal(modal) {
    var root = $("modal-root");
    root.innerHTML = "";
    var backdrop = el("div", "modal-backdrop");
    backdrop.appendChild(modal);
    root.appendChild(backdrop);

    function onKey(e) { if (e.key === "Escape") close(); }
    document.addEventListener("keydown", onKey);

    function close() {
      document.removeEventListener("keydown", onKey);
      root.innerHTML = "";
    }
    return close;
  }

  // ---------- views ----------
  // Settings used to be a dialog. It holds eight editable word lists and a
  // full system prompt, so it is a page: scrollable, linkable, and impossible
  // to lose to a stray click.
  function showView(name) {
    state.view = name;
    $("view-scans").hidden = name !== "scans";
    $("view-settings").hidden = name !== "settings";
    if (name === "settings" && location.hash !== "#settings") location.hash = "#settings";
    if (name === "scans" && location.hash === "#settings") {
      history.replaceState(null, "", location.pathname + location.search);
    }
    window.scrollTo(0, 0);
  }

  function leaveSettings() {
    if (state.dirty && !window.confirm("Leave settings? Unsaved changes will be lost.")) return;
    state.dirty = false;
    showView("scans");
  }

  function openSettings(focus) {
    if (!LIVE) return Promise.resolve();
    var ready = state.patterns
      ? Promise.resolve(state.patterns)
      : api("/api/patterns").then(function (d) { state.patterns = d; return d; });
    return ready.then(function () {
      renderSettingsPage();
      showView("settings");
      if (!focus) return;
      var target = $("set-" + focus);
      if (!target) return;
      target.scrollIntoView();
      var first = target.querySelector("input, textarea");
      if (first) first.focus();
    }).catch(function (err) {
      alert("Could not load settings: " + err.message);
    });
  }

  // ---------- settings (live mode only) ----------
  function loadSettings() {
    return api("/api/settings").then(function (data) {
      state.settings = data.settings || {};
      state.providers = data.providers || [];
      return state.settings;
    }).catch(function () { return null; });
  }

  function loadStatus() {
    return api("/api/status").then(function (data) {
      state.status = data;
      renderBanner();
      return data;
    }).catch(function () { return null; });
  }

  function providerById(id) {
    for (var i = 0; i < state.providers.length; i++) {
      if (state.providers[i].id === id) return state.providers[i];
    }
    return null;
  }

  // A banner only when something would actually degrade a run — never as
  // decoration, or people stop reading it.
  function renderBanner() {
    var host = $("banner");
    if (!host) return;
    host.innerHTML = "";
    var st = state.status;
    if (!st) return;

    var problems = [];
    (st.tools || []).forEach(function (t) {
      if (!t.available) problems.push({ level: "bad", text: t.name + " is not installed — " + t.hint });
    });
    if (st.github.error) {
      // A rejected token is worse than no token: requests fail outright
      // instead of falling back to the anonymous rate limit.
      problems.push({
        level: "bad",
        text: "GitHub rejected the stored token (" + st.github.error + "). Scans will find nothing until it is fixed.",
        action: "github",
      });
    } else if (!st.github.token) {
      problems.push({
        level: "warn",
        text: "No GitHub token — capped at 60 requests/hour. A token with no scopes raises it to 5000.",
        action: "github",
      });
    } else if (st.github.remaining !== null && st.github.remaining < 100) {
      problems.push({
        level: "warn",
        text: "GitHub rate limit low: " + st.github.remaining + " of " + st.github.limit + " left.",
      });
    }
    if (st.ai.enabled && !st.ai.key) {
      problems.push({ level: "warn", text: "AI triage is on but no API key is set.", action: "ai" });
    }
    if (st.ai.enabled && st.ai.key && !st.ai.sdk) {
      problems.push({
        level: "warn",
        text: 'AI triage needs the Anthropic SDK: pip install "gitanalyzer[ai]" — or pick an OpenAI-format provider.',
        action: "ai",
      });
    }

    problems.forEach(function (p) {
      var row = el("div", "banner " + p.level);
      row.appendChild(el("span", null, p.text));
      if (p.action) {
        var fix = el("button", "ghost", "Settings");
        fix.onclick = function () { openSettings(p.action); };
        row.appendChild(fix);
      }
      host.appendChild(row);
    });
  }

  // ---------- form builders ----------
  function field(label, id, type, value, attrs) {
    var wrap = el("div");
    var tag = el("label", null, label);
    tag.htmlFor = id;
    wrap.appendChild(tag);
    var input = el("input");
    input.id = id;
    input.type = type || "text";
    if (value !== undefined && value !== null) input.value = value;
    Object.keys(attrs || {}).forEach(function (k) { input.setAttribute(k, attrs[k]); });
    wrap.appendChild(input);
    return wrap;
  }

  function area(label, id, value, placeholder, rows) {
    var wrap = el("div");
    var tag = el("label", null, label);
    tag.htmlFor = id;
    wrap.appendChild(tag);
    var input = el("textarea");
    input.id = id;
    input.value = value || "";
    if (placeholder) input.placeholder = placeholder;
    input.style.minHeight = (rows || 3) * 22 + "px";
    wrap.appendChild(input);
    return wrap;
  }

  function block(summary) {
    var node = el("details", "block");
    node.appendChild(el("summary", null, summary));
    return node;
  }

  function checkbox(label, id, checked, tip) {
    var wrap = el("label", "check");
    if (tip) wrap.title = tip;
    var input = el("input");
    input.type = "checkbox";
    input.id = id;
    input.checked = !!checked;
    wrap.appendChild(input);
    wrap.appendChild(document.createTextNode(" " + label));
    return wrap;
  }

  // What each knob actually does, written once and shown in both places that
  // offer it: the Settings panel and the New scan dialog. Every limit treats
  // 0 as "no limit", so the tips say what 0 does rather than leaving it to be
  // discovered on a scan that came back empty.
  var TIPS = {
    accounts: "One GitHub login or profile URL per line. Lines starting with # are ignored. " +
      "Only public repositories are read.",
    keywords: "Your own names and domains — a finding containing one is flagged as a keyword " +
      "match, sorted to the top and never dropped by the per-repo cap.",
    patterns: "Literal strings searched in addition to the built-in ripgrep patterns. " +
      "Project code names, internal hostnames, anything you would grep for by hand.",
    age: "Skips repositories nobody has pushed to in this long (GitHub's pushed_at). " +
      "0 = no age limit: every repository is scanned however old it is.",
    size: "Skips repositories bigger than this, so one huge monorepo cannot stall the run. " +
      "0 = no size limit.",
    cooldown: "Skips an account scanned more recently than this, so re-running a long list " +
      "does not redo last night's work. 0 = always rescan.",
    cap: "Keeps at most this many findings per repository. Secrets and keyword matches are " +
      "never the ones dropped — the cap only trims plain URLs. 0 = keep everything.",
    forks: "A fork's findings almost always belong to the upstream project, not to the " +
      "account you are assessing.",
    archived: "Archived repositories are read-only. Usually already triaged, and nothing " +
      "new can land in one.",
    trufflehog: "Credentials across the full git history, including deleted commits, with " +
      "live verification against the provider where possible.",
    ripgrep: "The working tree only: URLs, internal infrastructure and config files that " +
      "TruffleHog does not treat as secrets.",
    ai: "Sends the top findings to a model that marks each one confirmed, needs-review or " +
      "dismissed, which adjusts the score. Credential values are masked first.",
  };

  function panel(id, title, lead) {
    var node = el("section", "panel form");
    node.id = "set-" + id;
    node.appendChild(el("h2", null, title));
    if (lead) node.appendChild(el("p", "lead", lead));
    return node;
  }

  function cols() { return el("div", "cols"); }

  function note(text) {
    var node = el("div", "note");
    node.innerHTML = text;
    return node;
  }

  // ---------- the settings page ----------
  var SECTIONS = [
    ["github", "GitHub access"],
    ["scan", "Scan defaults"],
    ["timing", "Timeouts & pacing"],
    ["lists", "Word lists"],
    ["ai", "AI triage"],
    ["prompt", "Triage prompt"],
    ["storage", "Storage & secrets"],
  ];

  function saveMessage(text, cls) {
    var node = $("save-msg");
    node.className = "save-msg" + (cls ? " " + cls : "");
    node.textContent = text;
  }

  function markDirty() {
    if (state.view !== "settings") return;
    state.dirty = true;
    saveMessage("Unsaved changes.", "dirty");
  }

  function renderSettingsPage() {
    var cfg = state.settings || {};
    var pats = state.patterns || {};
    var body = $("settings-body");
    var nav = $("settings-nav");
    body.innerHTML = "";
    nav.innerHTML = "";
    state.ui = {};
    state.dirty = false;
    saveMessage("Saved settings are the defaults every new scan starts from.", "");

    $("settings-where").textContent =
      "Stored in " + ((state.status && state.status.results_dir) || "results") +
      "/.settings.json, owner-readable only.";

    SECTIONS.forEach(function (pair) {
      var link = el("a", null, pair[1]);
      link.href = "#set-" + pair[0];
      link.dataset.section = "set-" + pair[0];
      link.onclick = function (e) {
        e.preventDefault();
        var target = $("set-" + pair[0]);
        if (target) target.scrollIntoView();
      };
      nav.appendChild(link);
    });

    body.appendChild(githubPanel(cfg));
    body.appendChild(scanPanel(cfg));
    body.appendChild(timingPanel(cfg));
    body.appendChild(listsPanel(pats));
    body.appendChild(aiPanel(cfg));
    body.appendChild(promptPanel(cfg, pats));
    body.appendChild(storagePanel(cfg));
    syncNav();
  }

  function syncNav() {
    var links = $("settings-nav").children;
    var current = null;
    for (var i = 0; i < links.length; i++) {
      var section = $(links[i].dataset.section);
      if (section && section.getBoundingClientRect().top <= 120) current = links[i];
    }
    for (var j = 0; j < links.length; j++) {
      links[j].className = links[j] === current ? "active" : "";
    }
  }

  function githubPanel(cfg) {
    var node = panel("github", "GitHub access",
      "Only public data is read, so a token with no scopes at all is enough. " +
      "Its only job is the rate limit: 60 requests an hour without one, 5000 with it.");
    var st = state.status;
    if (st && st.github.token) {
      node.appendChild(note(
        "Token active, from <code>" + attr(st.github.source) + "</code>" +
        (st.github.remaining !== null
          ? " — " + st.github.remaining + " of " + st.github.limit + " requests left this hour."
          : ".")));
    }
    var gh = field(
      cfg.github_token_set ? "Token (stored: " + cfg.github_token_hint + ") — type to replace" : "Token",
      "s-gh-token", "password", "", { placeholder: "ghp_...", autocomplete: "off" });
    node.appendChild(gh);
    state.ui.ghInput = gh.querySelector("input");
    if (cfg.github_token_set) {
      var clear = el("button", "ghost", "Clear stored token");
      clear.onclick = function () {
        saveSettings({ github_token: "" }).then(function () { openSettings("github"); });
      };
      node.appendChild(clear);
    }
    node.appendChild(note(
      "The environment still wins: if <code>GITHUB_TOKEN</code> is exported, " +
      "that is the token a scan uses and nothing has to be written to disk."));
    return node;
  }

  function scanPanel(cfg) {
    var node = panel("scan", "Scan defaults",
      "What a new scan starts from. The New scan dialog can override any of it for a single run.");
    node.appendChild(field(
      "Keywords (comma separated) — matches are promoted and never capped by the per-repo limit",
      "s-keywords", "text", (cfg.keywords || []).join(", "),
      { placeholder: "acme, acme-internal, acmecorp.com", title: TIPS.keywords }));
    node.appendChild(field("Extra literal patterns (comma separated) — searched in addition to the ripgrep list",
      "s-patterns", "text", (cfg.custom_patterns || []).join(", "),
      { placeholder: "project-codename, internal-host", title: TIPS.patterns }));

    var grid = cols();
    grid.appendChild(field("Max repo age (months, 0 = any)", "s-age", "number",
      cfg.max_repo_age_months, { min: "0", title: TIPS.age }));
    grid.appendChild(field("Max repo size (MB, 0 = any)", "s-size", "number",
      cfg.max_repo_size_mb, { min: "0", title: TIPS.size }));
    grid.appendChild(field("Rescan cooldown (days, 0 = always)", "s-cooldown", "number",
      cfg.rescan_days, { min: "0", title: TIPS.cooldown }));
    grid.appendChild(field("Findings cap per repo (0 = all)", "s-cap", "number",
      cfg.max_findings_per_repo, { min: "0", title: TIPS.cap }));
    node.appendChild(grid);

    var toggles = cols();
    var left = el("div");
    left.appendChild(checkbox("skip forks", "s-forks", cfg.skip_forks, TIPS.forks));
    left.appendChild(checkbox("skip archived repositories", "s-archived", cfg.skip_archived, TIPS.archived));
    var right = el("div");
    right.appendChild(checkbox("TruffleHog — credentials, full git history", "s-th", cfg.use_trufflehog, TIPS.trufflehog));
    right.appendChild(checkbox("ripgrep — URLs, infrastructure, config", "s-rg", cfg.use_ripgrep, TIPS.ripgrep));
    toggles.appendChild(left);
    toggles.appendChild(right);
    node.appendChild(toggles);
    return node;
  }

  function timingPanel(cfg) {
    var node = panel("timing", "Timeouts & pacing",
      "Per-repository limits. The delays are what keep a long account list from " +
      "looking like abuse to GitHub.");
    var grid = cols();
    grid.appendChild(field("Clone depth (0 = full history)", "s-depth", "number", cfg.clone_depth, { min: "0" }));
    grid.appendChild(field("Clone timeout (s)", "s-t-clone", "number", cfg.clone_timeout, { min: "10" }));
    grid.appendChild(field("TruffleHog timeout (s)", "s-t-th", "number", cfg.trufflehog_timeout, { min: "10" }));
    grid.appendChild(field("ripgrep timeout (s)", "s-t-rg", "number", cfg.ripgrep_timeout, { min: "10" }));
    grid.appendChild(field("Delay between repos (s)", "s-d-repo", "text", cfg.delay_between_repos));
    grid.appendChild(field("Delay between accounts (s)", "s-d-acct", "text", cfg.delay_between_accounts));
    node.appendChild(grid);
    node.appendChild(note(
      "Clone depth 0 means full history, which is what TruffleHog walks. A shallow " +
      "clone is only useful with TruffleHog off: it loses every secret that was " +
      "committed and then deleted — the ones most worth finding."));
    return node;
  }

  function listsPanel(pats) {
    var node = panel("lists", "Word lists",
      "Everything the scan looks for and everything it throws away. These are the " +
      "lists from patterns.py, editable here: one entry per line. Clear a box to put " +
      "the built-in list back.");
    var order = pats.order || [];
    var grid = el("div", "lists");
    order.forEach(function (name) {
      grid.appendChild(wordlistEditor(name, pats));
    });
    node.appendChild(grid);
    node.appendChild(note(
      "ripgrep patterns use Rust regex syntax, which has no look-around. A pattern " +
      "it cannot compile is rejected when you save — rather than silently searching " +
      "for nothing on the next scan."));
    return node;
  }

  // Only the regex list has entries long enough to need the whole width; the
  // longest built-in glob is 27 characters and a detector name is five.
  var WIDE_LISTS = { rg_patterns: 1 };

  function fitRows(box) {
    var lines = box.value ? box.value.split("\n").length : 0;
    box.rows = Math.max(8, Math.min(lines + 1, 20));
  }

  function wordlistEditor(name, pats) {
    var label = (pats.labels || {})[name] || { title: name, hint: "" };
    var builtin = (pats.builtin || {})[name] || [];
    var current = (pats.effective || {})[name] || [];

    var wrap = el("div", WIDE_LISTS[name] ? "wl wide" : "wl");
    // Two cells: a title that may wrap, and actions that never do.
    var head = el("div", "wl-head");
    var title = el("div", "wl-title");
    title.appendChild(el("b", null, label.title));
    // The badge only appears when the list is no longer the built-in one:
    // announcing the default on all eight boxes is noise, not information.
    var tag = el("span", "tag", "custom");
    tag.hidden = true;
    title.appendChild(tag);
    head.appendChild(title);
    var acts = el("div", "wl-actions");
    var count = el("span", "count");
    acts.appendChild(count);
    var reset = el("button", "ghost", "Reset");
    reset.title = "Put the built-in list back (" + builtin.length + " entries)";
    acts.appendChild(reset);
    head.appendChild(acts);
    wrap.appendChild(head);
    if (label.hint) wrap.appendChild(el("p", null, label.hint));

    var box = el("textarea");
    box.id = "wl-" + name;
    box.value = current.join("\n");
    box.spellcheck = false;
    box.setAttribute("wrap", "off");
    // Open at the size of the list, within reason: enough rows to read a short
    // list whole, capped so one long list does not bury the seven below it.
    fitRows(box);
    wrap.appendChild(box);

    function sync() {
      var items = rawLines(box.value);
      var changed = items.join("\n") !== builtin.join("\n");
      count.textContent = items.length + (changed ? " / " + builtin.length + " built-in" : " entries");
      wrap.className = "wl" + (WIDE_LISTS[name] ? " wide" : "") + (changed ? " changed" : "");
      tag.hidden = !changed;
      reset.disabled = !changed;
    }
    box.oninput = sync;
    reset.onclick = function () {
      box.value = builtin.join("\n");
      fitRows(box);
      sync();
      markDirty();
    };
    sync();
    return wrap;
  }

  function aiPanel(cfg) {
    var node = panel("ai", "AI triage",
      "Off by default. When on, the top findings are sent to a model that marks each " +
      "one confirmed, needs-review or dismissed, and the verdict adjusts the score. " +
      "Credential values are masked first.");
    node.appendChild(checkbox("enable AI triage on new scans", "s-ai", cfg.ai_triage));

    var grid = cols();

    var provWrap = el("div");
    var provLabel = el("label", null, "Provider");
    provLabel.htmlFor = "s-ai-provider";
    provWrap.appendChild(provLabel);
    var prov = el("select");
    prov.id = "s-ai-provider";
    state.providers.forEach(function (p) {
      var opt = el("option", null, p.label);
      opt.value = p.id;
      if (p.id === cfg.ai_provider) opt.selected = true;
      prov.appendChild(opt);
    });
    provWrap.appendChild(prov);
    grid.appendChild(provWrap);

    var urlField = field("Endpoint", "s-ai-url", "text", cfg.ai_base_url,
      { placeholder: "https://api.anthropic.com" });
    grid.appendChild(urlField);

    var modelWrap = el("div", "wide-field");
    var modelLabel = el("label", null, "Model");
    modelLabel.htmlFor = "s-ai-model";
    modelWrap.appendChild(modelLabel);
    var modelRow = el("div", "row");
    var model = el("input");
    model.id = "s-ai-model";
    model.setAttribute("list", "s-ai-models");
    model.value = cfg.ai_model || "";
    modelRow.appendChild(model);
    var fetchBtn = el("button", "ghost", "Load from endpoint");
    modelRow.appendChild(fetchBtn);
    modelWrap.appendChild(modelRow);
    var datalist = el("datalist");
    datalist.id = "s-ai-models";
    modelWrap.appendChild(datalist);
    var modelNote = el("div", "hint");
    modelWrap.appendChild(modelNote);
    grid.appendChild(modelWrap);

    var keyField = field(
      cfg.ai_key_set ? "API key (stored: " + cfg.ai_key_hint + ") — type to replace" : "API key",
      "s-ai-key", "password", "", { placeholder: "sk-...", autocomplete: "off" });
    keyField.className = "wide-field";
    grid.appendChild(keyField);
    node.appendChild(grid);

    if (cfg.ai_key_set) {
      var clearAi = el("button", "ghost", "Clear stored key");
      clearAi.onclick = function () {
        saveSettings({ ai_key: "" }).then(function () { openSettings("ai"); });
      };
      node.appendChild(clearAi);
    }

    var aiGrid = cols();
    aiGrid.appendChild(field("Max findings to triage", "s-ai-max", "number", cfg.ai_max_findings, { min: "1" }));
    aiGrid.appendChild(field("Findings per request", "s-ai-batch", "number", cfg.ai_batch_size, { min: "1" }));
    aiGrid.appendChild(field("Request timeout (s)", "s-ai-timeout", "number", cfg.ai_timeout, { min: "10" }));
    node.appendChild(aiGrid);
    node.appendChild(checkbox("mask credential values before sending (recommended)", "s-ai-redact", cfg.ai_redact));

    state.ui.prov = prov;
    state.ui.model = model;
    state.ui.urlInput = urlField.querySelector("input");

    function fillModels(list) {
      datalist.innerHTML = "";
      (list || []).forEach(function (name) {
        var opt = el("option");
        opt.value = name;
        datalist.appendChild(opt);
      });
    }

    function syncProvider() {
      var p = providerById(prov.value);
      if (!p) return;
      if (p.id !== "custom") state.ui.urlInput.value = p.base_url;
      fillModels(p.models);
      modelNote.textContent = p.models.length
        ? p.models.length + " known models — Load asks the endpoint for the current list."
        : "Type a model id, or press Load to ask the endpoint (needs the API key above).";
    }
    prov.onchange = function () {
      syncProvider();
      var p = providerById(prov.value);
      if (!p) return;
      // Never carry a model id across providers: `claude-opus-5-5` pointed at
      // DeepSeek is a guaranteed failure, and a silent one.
      if (p.models.length) model.value = p.models[0];
      else if (p.models.indexOf(model.value) === -1) model.value = "";
    };
    syncProvider();

    fetchBtn.onclick = function () {
      fetchBtn.disabled = true;
      fetchBtn.textContent = "Loading...";
      api("/api/ai/models", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ai_base_url: state.ui.urlInput.value.trim(),
          ai_api: (providerById(prov.value) || {}).api || "",
          ai_key: $("s-ai-key").value.trim(),
        }),
      }).then(function (res) {
        fillModels(res.models);
        modelNote.textContent = res.models.length + " models offered by this endpoint.";
      }).catch(function (err) {
        modelNote.textContent = "Could not list models: " + err.message;
      }).then(function () {
        fetchBtn.disabled = false;
        fetchBtn.textContent = "Load from endpoint";
      });
    };
    return node;
  }

  function promptPanel(cfg, pats) {
    var node = panel("prompt", "Triage prompt",
      "What the model is told before it sees the findings. Empty means the built-in " +
      "prompt. Whatever you write must still ask for the same JSON array of verdicts, " +
      "or the reply cannot be parsed and the whole batch is ignored.");
    node.appendChild(area("System prompt", "s-ai-prompt", cfg.ai_system_prompt,
      "(using the built-in prompt)", 16));
    var row = el("div", "row");
    var load = el("button", "ghost", "Load the built-in prompt");
    load.onclick = function () {
      $("s-ai-prompt").value = pats.default_prompt || "";
      markDirty();
    };
    var reset = el("button", "ghost", "Reset to built-in");
    reset.onclick = function () {
      $("s-ai-prompt").value = "";
      markDirty();
    };
    row.appendChild(load);
    row.appendChild(reset);
    node.appendChild(row);

    var ref = block("Show the built-in prompt");
    ref.addEventListener("toggle", function () {
      if (!ref.open || ref.dataset.loaded) return;
      ref.dataset.loaded = "1";
      var pre = el("pre", null, pats.default_prompt || "");
      pre.style.whiteSpace = "pre-wrap";
      pre.style.fontSize = "12.5px";
      pre.style.color = "var(--fg-muted)";
      ref.appendChild(pre);
    });
    node.appendChild(ref);
    return node;
  }

  function storagePanel(cfg) {
    var node = panel("storage", "Storage & secrets",
      "Nothing here leaves the machine unless AI triage is on.");
    var st = state.status || {};
    node.appendChild(note(
      "<b>Scans</b> are JSON files in <code>" + attr(st.results_dir || "results") + "</code>. " +
      "They hold matched credential material, so treat that directory like the " +
      "secrets it contains.<br><br>" +
      "<b>Settings</b> live in <code>.settings.json</code> beside them, written with " +
      "mode 0600. Tokens are kept out of every scan file and the API only ever " +
      "returns a masked hint, never the value.<br><br>" +
      "<b>Cloned code</b> is written to a temporary directory and deleted as soon as " +
      "the repository has been scanned. Nothing of it is kept."));
    if (st.ai && st.ai.enabled) {
      node.appendChild(note(
        "AI triage is <b>on</b>: findings go to <code>" + attr(st.ai.endpoint || "") + "</code>" +
        (cfg.ai_redact === false
          ? " with credential values <b>unmasked</b>."
          : " with credential values masked.")));
    }
    return node;
  }

  function collectSettings() {
    var pats = state.patterns || {};
    var wordlists = {};
    (pats.order || []).forEach(function (name) {
      var box = $("wl-" + name);
      if (!box) return;
      var items = rawLines(box.value);
      var builtin = (pats.builtin || {})[name] || [];
      // An empty list means "use the built-in one", and so does a list that is
      // identical to it: storing a copy would freeze it against future updates.
      wordlists[name] = items.join("\n") === builtin.join("\n") ? [] : items;
    });

    var payload = {
      keywords: csv($("s-keywords").value),
      custom_patterns: csv($("s-patterns").value),
      max_repo_age_months: num($("s-age").value, 24),
      max_repo_size_mb: num($("s-size").value, 500),
      rescan_days: num($("s-cooldown").value, 0),
      max_findings_per_repo: num($("s-cap").value, 0),
      skip_forks: $("s-forks").checked,
      skip_archived: $("s-archived").checked,
      use_trufflehog: $("s-th").checked,
      use_ripgrep: $("s-rg").checked,
      clone_depth: num($("s-depth").value, 0),
      clone_timeout: num($("s-t-clone").value, 120),
      trufflehog_timeout: num($("s-t-th").value, 300),
      ripgrep_timeout: num($("s-t-rg").value, 600),
      delay_between_repos: parseFloat($("s-d-repo").value) || 0,
      delay_between_accounts: parseFloat($("s-d-acct").value) || 0,
      wordlists: wordlists,
      ai_triage: $("s-ai").checked,
      ai_provider: state.ui.prov.value,
      ai_base_url: state.ui.urlInput.value.trim(),
      ai_model: state.ui.model.value.trim(),
      ai_max_findings: num($("s-ai-max").value, 150),
      ai_batch_size: num($("s-ai-batch").value, 15),
      ai_timeout: num($("s-ai-timeout").value, 120),
      ai_redact: $("s-ai-redact").checked,
      ai_system_prompt: $("s-ai-prompt").value.trim(),
    };
    // Secrets are only sent when actually typed, so saving the rest of the
    // form never round-trips a token through the browser.
    var gh = state.ui.ghInput.value.trim();
    if (gh) payload.github_token = gh;
    var aiKey = $("s-ai-key").value.trim();
    if (aiKey) payload.ai_key = aiKey;
    return payload;
  }

  function submitSettings() {
    var button = $("set-save");
    button.disabled = true;
    button.textContent = "Saving...";
    saveMessage("Saving...", "");
    return saveSettings(collectSettings()).then(function () {
      // Re-read the word lists: the server decides what counts as an override.
      return api("/api/patterns").then(function (d) { state.patterns = d; });
    }).then(function () {
      state.dirty = false;
      renderSettingsPage();
      saveMessage("Saved.", "ok");
    }).catch(function (err) {
      saveMessage("Could not save: " + err.message, "bad");
    }).then(function () {
      button.disabled = false;
      button.textContent = "Save";
    });
  }

  function csv(text) {
    return String(text || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  }
  // Word list lines are kept verbatim apart from blank ones: a regex may end in
  // a meaningful space, and it is the server that normalizes the rest.
  function rawLines(text) {
    return String(text || "").split("\n").filter(function (s) { return s.trim(); });
  }
  function num(value, fallback) {
    var n = parseInt(value, 10);
    return isNaN(n) ? fallback : n;
  }

  function saveSettings(payload) {
    return api("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(function (data) {
      state.settings = data.settings || {};
      return loadStatus();
    });
  }

  // ---------- new scan modal (live mode only) ----------
  // `0` is a meaningful value in every one of these fields, so it is written
  // out rather than skipped the way a falsy default usually would be.
  function numField(id, label, value, tip) {
    var shown = (value === undefined || value === null || value === "") ? 0 : value;
    return '<div title="' + attr(tip) + '">' +
      '<label for="' + id + '">' + label + ' <span class="zero">0 = no limit</span></label>' +
      '<input id="' + id + '" type="number" min="0" value="' + attr(shown) + '">' +
      '</div>';
  }

  function openScanModal() {
    var cfg = state.settings || {};
    var aiHint = cfg.ai_key_set || (state.status && state.status.ai.key)
      ? "AI triage (" + (cfg.ai_model || "configured") + ")"
      : "AI triage (no API key set — configure it in Settings)";
    var modal = el("div", "modal form");
    modal.innerHTML =
      '<h2>New scan</h2>' +
      '<p class="hint">Only scan accounts you are authorized to assess.</p>' +
      '<label for="m-accounts" title="' + attr(TIPS.accounts) + '">GitHub accounts (one per line)</label>' +
      '<textarea id="m-accounts" title="' + attr(TIPS.accounts) + '" placeholder="octocat&#10;https://github.com/defunkt"></textarea>' +
      '<label for="m-keywords" title="' + attr(TIPS.keywords) + '">Keywords (comma separated, optional)</label>' +
      '<input id="m-keywords" title="' + attr(TIPS.keywords) + '" value="' + attr((cfg.keywords || []).join(", ")) + '" placeholder="acme, acme-internal, acmecorp.com">' +
      '<div class="grid">' +
      numField("m-age", "Max repo age (months)", cfg.max_repo_age_months, TIPS.age) +
      numField("m-size", "Max repo size (MB)", cfg.max_repo_size_mb, TIPS.size) +
      numField("m-cooldown", "Rescan cooldown (days)", cfg.rescan_days, TIPS.cooldown) +
      numField("m-cap", "Findings cap per repo", cfg.max_findings_per_repo, TIPS.cap) +
      '</div>' +
      '<label class="check" title="' + attr(TIPS.forks) + '"><input type="checkbox" id="m-forks"' + (cfg.skip_forks === false ? '' : ' checked') + '> skip forks</label>' +
      '<label class="check" title="' + attr(TIPS.archived) + '"><input type="checkbox" id="m-archived"' + (cfg.skip_archived === false ? '' : ' checked') + '> skip archived</label>' +
      '<label class="check" title="' + attr(TIPS.ai) + '"><input type="checkbox" id="m-ai"' + (cfg.ai_triage ? ' checked' : '') + '> ' + attr(aiHint) + '</label>' +
      '<p class="hint">Defaults come from Settings; 0 in any limit means no limit. ' +
      'Changes here apply to this scan only — hover a field to see what it does.</p>' +
      '<div class="foot"><button class="ghost" id="m-settings">Settings</button>' +
      '<span class="spacer"></span>' +
      '<button class="ghost" id="m-cancel">Cancel</button>' +
      '<button class="primary" id="m-start">Start scan</button></div>';
    var close = mountModal(modal);
    $("m-cancel").onclick = close;
    $("m-settings").onclick = function () { close(); openSettings(); };
    $("m-start").onclick = function () {
      var accounts = $("m-accounts").value.split("\n")
        .map(function (s) { return s.trim(); })
        .filter(function (s) { return s && s.charAt(0) !== "#"; });
      if (!accounts.length) { $("m-accounts").focus(); return; }
      $("m-start").disabled = true;
      $("m-start").textContent = "Starting...";
      api("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          accounts: accounts,
          keywords: $("m-keywords").value.split(",").map(function (s) { return s.trim(); }).filter(Boolean),
          // num(), not `|| default`: a typed 0 means no limit and must survive.
          max_repo_age_months: num($("m-age").value, 0),
          max_repo_size_mb: num($("m-size").value, 0),
          rescan_days: num($("m-cooldown").value, 0),
          max_findings_per_repo: num($("m-cap").value, 0),
          skip_forks: $("m-forks").checked,
          skip_archived: $("m-archived").checked,
          ai_triage: $("m-ai").checked,
        }),
      }).then(function (res) {
        close();
        refreshScans().then(function () { selectScan(res.id); });
      }).catch(function (err) {
        $("m-start").disabled = false;
        $("m-start").textContent = "Start scan";
        alert("Could not start scan: " + err.message);
      });
    };
    $("m-accounts").focus();
  }

  // ---------- live data ----------
  function refreshScans() {
    return api("/api/scans").then(function (data) {
      state.scans = data.scans || [];
      renderSidebar();
      return state.scans;
    }).catch(function () { return []; });
  }

  function deleteScan(scan) {
    if (scan.status === "running") {
      alert("That scan is still running. Cancel it first, then delete it.");
      return;
    }
    var who = (scan.accounts || []).join(", ") || scan.label || scan.id;
    var total = (scan.stats || {}).total_findings || 0;
    // Spelling out what is lost, because the findings in a scan file are the
    // only copy: the repositories are cloned to a temp dir and thrown away.
    if (!window.confirm(
      "Delete the scan of " + who + "?\n\n" +
      total + " findings · " + fmtDate(scan.started_at) + "\n\n" +
      "Its file is removed from the results directory. This cannot be undone.")) {
      return;
    }
    var wasOpen = state.selectedId === scan.id;
    api("/api/scans/" + encodeURIComponent(scan.id), { method: "DELETE" }).then(function () {
      return refreshScans().then(function (scans) {
        if (!wasOpen) return null;
        // The open scan just went away: fall back to the newest one left, or
        // to the empty state rather than a view of a file that is gone.
        state.scan = null;
        state.selectedId = null;
        state.openAccounts = {};
        state.openRepos = {};
        if (scans.length) return selectScan(scans[0].id);
        clearTimeout(state.timer);
        render();
        return null;
      });
    }).catch(function (err) {
      alert("Could not delete the scan: " + err.message);
      refreshScans();
    });
  }

  function selectScan(id) {
    state.selectedId = id;
    return api("/api/scans/" + encodeURIComponent(id)).then(function (scan) {
      state.scan = scan;
      if (!Object.keys(state.openAccounts).length) {
        var groups = groupByAccount(visibleFindings());
        if (groups[0]) state.openAccounts[groups[0].account] = true;
      }
      render();
      schedulePoll();
    });
  }

  function schedulePoll() {
    clearTimeout(state.timer);
    var running = state.scan && state.scan.status === "running";
    if (!running) return;
    state.timer = setTimeout(function () {
      api("/api/scans/" + encodeURIComponent(state.selectedId)).then(function (scan) {
        state.scan = scan;
        render();
        schedulePoll();
      }).catch(schedulePoll);
    }, 3000);
  }

  // ---------- wiring ----------
  function init() {
    ["f-severity", "f-scanner", "f-account", "f-type", "f-ai"].forEach(function (id) {
      $(id).onchange = render;
    });
    $("f-verified").onchange = render;
    $("f-noise").onchange = render;
    $("q").oninput = debounce(render, 180);
    $("expand-all").onclick = function () {
      groupByAccount(visibleFindings()).forEach(function (g) {
        state.openAccounts[g.account] = true;
        g.repos.forEach(function (r) { state.openRepos[g.account + "/" + r.repo] = true; });
      });
      render();
    };
    $("collapse-all").onclick = function () {
      state.openAccounts = {};
      state.openRepos = {};
      render();
    };

    var actions = $("header-actions");
    var md = el("button", "ghost", "Export .md");
    md.id = "export-md";
    md.onclick = function () {
      if (!state.scan) return;
      download("gitanalyzer-" + state.scan.id + ".md", toMarkdown(), "text/markdown");
    };
    actions.appendChild(md);

    if (LIVE) {
      $("sidebar").hidden = false;
      var html = el("button", "ghost", "Export .html");
      html.id = "export-html";
      html.onclick = function () {
        if (!state.selectedId) return;
        window.location.href = "/api/scans/" + encodeURIComponent(state.selectedId) + "/report.html";
      };
      actions.appendChild(html);

      var fresh = el("button", "ghost", "Refresh");
      fresh.onclick = function () {
        refreshScans();
        if (state.selectedId) selectScan(state.selectedId);
      };
      actions.appendChild(fresh);

      var gear = el("button", "ghost", "Settings");
      gear.onclick = function () {
        if (state.view === "settings") showView("scans");
        else openSettings();
      };
      actions.appendChild(gear);

      var start = el("button", "primary", "New scan");
      start.onclick = openScanModal;
      actions.appendChild(start);

      // Settings page wiring. Any edit arms the save bar, so a half-finished
      // form cannot be mistaken for a saved one.
      $("settings-body").addEventListener("input", markDirty);
      $("settings-body").addEventListener("change", markDirty);
      $("set-save").onclick = submitSettings;
      $("set-revert").onclick = function () {
        loadSettings().then(function () { renderSettingsPage(); });
      };
      $("set-back").onclick = function () { leaveSettings(); };
      window.addEventListener("scroll", function () {
        if (state.view === "settings") syncNav();
      }, { passive: true });
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && state.view === "settings" && !$("modal-root").firstChild) {
          leaveSettings();
        }
      });
      window.addEventListener("hashchange", function () {
        if (location.hash === "#settings") openSettings();
        else if (state.view === "settings") showView("scans");
      });

      loadSettings().then(loadStatus).then(function () {
        if (location.hash === "#settings") openSettings();
      });
      setInterval(loadStatus, 60000);

      refreshScans().then(function (scans) {
        if (scans.length) selectScan(scans[0].id);
        else render();
      });
      setInterval(refreshScans, 10000);
    } else {
      render();
      var groups = groupByAccount(visibleFindings());
      if (groups[0]) { state.openAccounts[groups[0].account] = true; render(); }
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
