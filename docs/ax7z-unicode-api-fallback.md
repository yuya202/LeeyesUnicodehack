# ax7z Unicode archive API fallback

This branch adds a narrow fallback for `ax7z.spi` when Leeyes cannot obtain a
non-empty archive member list through the existing ANSI Susie API.

## ABI facts used by the adapter

The Leeyes archive-list caller consumes the ANSI `fileInfo` layout in
428-byte steps. The Unicode Susie `fileInfoW` layout is 828 bytes. The adapter
therefore never passes the W records directly to Leeyes; it copies the scalar
metadata and converts the two UTF-16 name fields into the ANSI layout,
including a zeroed terminator record.

The conversion preserves the original Unicode spelling in the existing
process-local lossy-display-name map whenever CP932 conversion is lossy or
best-fit. This allows the existing drawing path to restore the original name.

## Call sequence

1. Keep the current ANSI alias and direct-path attempts.
2. Only for `ax7z.spi`, when those attempts return no entries, call
   `GetArchiveInfoW` with the resolved UTF-16 archive path.
3. Convert the returned records into Leeyes' 428-byte ANSI ABI.
4. Remember that this archive was enumerated through the W API.
5. For a later `GetFile` call for that archive, try `GetFileW` with the same
   member position. If it fails, preserve the existing ANSI extraction path.

Other Susie plug-ins and archives are not routed through the new W fallback.

## Validation status

The branch includes a Windows 2022 / MSVC Win32 Release build workflow. A
successful CI build checks compilation and the output PE machine type only.
It does not prove that the selected Susie plug-in version behaves correctly
at runtime. Runtime verification must use a copy of the user's Leeyes folder;
the existing `Leeyes.exe` is not modified.
