# winget

The templates here are the winget manifests for `Pocketwire.Bridge`. `render.sh` fills them in
for one version; the release workflow does that and attaches the result to every release as
`winget-manifests.zip`.

## First version (once, by hand)

winget-pkgs only takes a new package from a pull request someone opens, so the first version
goes in by hand:

1. Fork [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) to your account.
2. Make a classic token with the `public_repo` scope.
3. On Windows, unzip `winget-manifests.zip` from the release and run:

   ```powershell
   winget install Microsoft.WingetCreate
   wingetcreate submit --token <token> manifests\p\Pocketwire\Bridge\<version>
   ```

4. In the pull request, accept the Microsoft CLA when the bot asks. The checks install the
   package in a sandbox; a reviewer merges it, which can take a few days.

## Every later version

Add the same token as the repository secret `WINGET_TOKEN`. The release workflow's `winget`
job then sends each new release to winget-pkgs on its own, once the package is listed there.

Users install and update with:

```powershell
winget install Pocketwire.Bridge
winget upgrade Pocketwire.Bridge
```
