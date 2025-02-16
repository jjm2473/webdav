package lib

import (
	"context"
	"io/fs"
	"mime"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/net/webdav"
)

// NoSniffFileInfo wraps any generic FileInfo interface and bypasses mime type sniffing.
type NoSniffFileInfo struct {
	os.FileInfo
}

func (w NoSniffFileInfo) ContentType(ctx context.Context) (contentType string, err error) {
	if mimeType := mime.TypeByExtension(path.Ext(w.FileInfo.Name())); mimeType != "" {
		// We can figure out the mime from the extension.
		return mimeType, nil
	} else {
		// We can't figure out the mime type without sniffing, call it an octet stream.
		return "application/octet-stream", nil
	}
}

type WebDavDir struct {
	webdav.Dir
	NoSniff bool
}

func (d WebDavDir) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	u := ctx.Value(WebDAVCtxUserKey).(*User)
	if u != nil {
		if !u.Allowed("/"+name, true) {
			return nil, filepath.SkipDir
		}
	}
	info, err := d.Dir.Stat(ctx, name)

	// Skip broken symbol link
	if err != nil && os.IsNotExist(err) {
		err = filepath.SkipDir
	}
	if err != nil {
		return nil, err
	}

	// Skip wrapping if NoSniff is off
	if !d.NoSniff {
		return info, err
	}

	return NoSniffFileInfo{info}, nil
}

func (d WebDavDir) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	u := ctx.Value(WebDAVCtxUserKey).(*User)
	if u != nil {
		if !u.Allowed("/"+name, true) {
			return nil, fs.ErrNotExist
		}
	}
	// Skip wrapping if NoSniff is off
	if !d.NoSniff {
		return d.Dir.OpenFile(ctx, name, flag, perm)
	}

	file, err := d.Dir.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}

	return WebDavFile{File: file}, nil
}

type WebDavFile struct {
	webdav.File
}

func (f WebDavFile) Stat() (os.FileInfo, error) {
	info, err := f.File.Stat()
	if err != nil {
		return nil, err
	}

	return NoSniffFileInfo{info}, nil
}

func (f WebDavFile) Readdir(count int) (fis []os.FileInfo, err error) {
	fis, err = f.File.Readdir(count)
	if err != nil {
		return nil, err
	}

	for i := range fis {
		fis[i] = NoSniffFileInfo{fis[i]}
	}
	return fis, nil
}
