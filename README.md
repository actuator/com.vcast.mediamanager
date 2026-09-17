# Verizon Cloud (Android) - "Dirty Stream" Path Traversal to Arbitrary File Write on Verizon Cloud Storage

> **Security Advisory**  
> Coordinated through VulnCheck.

## Advisory Details

| Field | Value |
|---|---|
| Researcher | Edward "Actuator" Warren |
| Coordinator | VulnCheck Submission ID: `ee7a170b-173a-47d1-b160-2125fafceadd` |
| Vendor / codebase | Verizon |
| Product / package | Verizon Cloud for Android - `com.vcast.mediamanager` |
| Version | `25.2.12` (`versionCode 2025021200`); `minSdk 29`, `targetSdk 35` |
| Vulnerability class | CWE-22 Path Traversal ("Dirty Stream") |
| Proven impact | Arbitrary attacker file injected into the victim's Verizon Cloud account |
| Status: | [Fixed] Remediation in Ver **26.7.10** |

<img width="1321" height="939" alt="vzCloudPOC" src="https://github.com/user-attachments/assets/1a68d1ef-0a67-4d6b-b271-bab94a82aee8" />


## Finding 1 - Unsanitized share-intent file copy (CWE-22, Dirty Stream)

Two activities are exported with no permission and accept a shared file via `ACTION_SEND` / `ACTION_SEND_MULTIPLE`:

| Exported activity (`com.newbay.syncdrive.android...`) | Intent filter |
|---|---|
| `ui.gui.activities.OneTouchUploadActivity` | `ACTION_SEND`, `ACTION_SEND_MULTIPLE`; `application/*` `audio/*` `image/*` `video/*` `text/*` `message/*` `multipart/*` |
| `ui.printshop.PrintShopCloudActivity` | `ACTION_SEND`, `ACTION_SEND_MULTIPLE`; `image/*` |

The copy sink takes the destination file name verbatim from the sender's content-provider `_display_name` (fallback `getLastPathSegment()`) and concatenates it to a staging directory with no basename stripping, canonicalization, or containment check.

Sink: `com.synchronoss.mobilecomponents.android.storage.util.c.a(Uri, String, callback)`:

```java
String name = uri.getLastPathSegment();                         // fallback (attacker)
Cursor q = resolver.query(uri, {"_display_name","_size"}, ...);
if (1 == q.getCount() && q.moveToFirst())
    name = q.getString(0);                                     // name := _display_name (ATTACKER)

File f = new File(tmpFolderPath + "/" + name);                  // no basename / canonical / containment
f.createNewFile();
qm0.k.b(resolver.openInputStream(uri), new FileOutputStream(f)); // attacker bytes -> path
```

A second, identical sink exists at `com.newbay.syncdrive.android.ui.printshop.a.b(Uri, String):File` (`new File(dir + "/" + _display_name)`; `a.c(List)` performs the copy).

The tainted URI at each sink traces to the exported entry's inbound `EXTRA_STREAM` - i.e. it is attacker-delivered, not a picker result.

## Finding 2 - Attacker file injected into the victim's cloud account

`OneTouchUploadActivity` does not stop at the local copy: the staged file is wrapped into an upload item and pushed to the signed-in Verizon Cloud account.

```java
a11  = mediaStoreHelper.a(uri, getTmpFolderPath(), cb);      // Finding 1 sink -> Uri.fromFile(staged)
item = createDescriptionItem(a11, type, action);             // name/size/type taken from staged file

startFileUpload(item)
    -> doUpload(list)
    -> doUploadHelper(list):

map["folder_items"] = [item];
map["one_touch_upload"] = true;
performAction(uploadFileActionHelper.c(this), map);          // -> cloud upload of attacker bytes
```

The uploaded object's name, MIME type, and content are attacker-controlled. An unprivileged local app with no storage, account, or network permissions can therefore inject an arbitrary file into the victim's cloud account.

`ACTION_SEND_MULTIPLE` permits multiple files to be injected per invocation.

### Preconditions

- Verizon Cloud is provisioned and signed in.
- The device is on Wi-Fi, which skips the cellular-backup confirmation dialog.
- No user interaction is required on the payload; the intake activity auto-finishes.

## Reproduction and Evidence

The PoC is a zero-permission application with a malicious `ContentProvider` whose `query()` returns an attacker-controlled `OpenableColumns.DISPLAY_NAME` and whose `openFile()` serves attacker-controlled bytes.

A launcher fires an explicit-component `ACTION_SEND` at the target with:

- `EXTRA_STREAM` set to the provider URI.
- `FLAG_GRANT_READ_URI_PERMISSION`.

### Reproduction

1. Install and sign in to Verizon Cloud and keep the device on Wi-Fi.
2. Install the PoC application. It requires no permissions.
3. Launch the PoC and tap **SEND -> OneTouchUploadActivity**.
4. Open the Verizon Cloud app or website, sync, and observe the injected file in the account.

### On-device evidence

Tested on a Google Pixel 10 Pro running Android API 36 against a production Verizon Cloud build with a signed-in account.

Attacker-app logcat:

```text
I DirtyStreamPOC: fired: SEND -> ...OneTouchUploadActivity
I DirtyStreamPOC: query(): served _display_name=ATTACKER_INJECTED_POC.jpg
I DirtyStreamPOC: openFile(): serving 637 bytes
```

**Result:** `ATTACKER_INJECTED_POC.jpg` - an image the victim never captured - appeared in the victim's Verizon Cloud gallery after sync.

The sink was also exercised through:

- `ACTION_SEND_MULTIPLE` to `OneTouchUploadActivity`.
- `ACTION_SEND` to `PrintShopCloudActivity`.

## Root Cause

The destination file name is sender-controlled content metadata (`_display_name` / `getLastPathSegment()`) concatenated into a filesystem path without validation, at a sink reachable from unprivileged exported activities.

The resulting staged file is then trusted by the upload pipeline.

1. Reduce the sender-supplied name to its basename with `new File(name).getName()` and reject names containing path separators or NUL.
2. Enforce canonical-path containment: `getCanonicalPath().startsWith(stagingDir)`, otherwise abort.
3. Prefer an application-generated UUID for the staging filename and treat `_display_name` only as display metadata.



---

Prepared by **Edward "Actuator" Warren**  
Actuator Security
