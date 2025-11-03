/* cbcp.c
 * by oli4vr
 *
 * Copy/Paste from/to stdin/stdout via the X11 clipboard
 */
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


int copy_to_clipboard(const char *str) {
    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "No X11 display found.\n");
        return 1;
    }
    XCloseDisplay(dpy); // Just checking availability

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 2;
    }
    if (pid > 0) {
        // Parent exits
        return 0;
    }

    // Child process: do the clipboard work
    dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "No X11 display found (child).\n");
        exit(1);
    }

    Window win = XCreateSimpleWindow(dpy, DefaultRootWindow(dpy), 0, 0, 1, 1, 0, 0, 0);
    Atom clipboard = XInternAtom(dpy, "CLIPBOARD", False);
    Atom utf8 = XInternAtom(dpy, "UTF8_STRING", False);
    Atom targets = XInternAtom(dpy, "TARGETS", False);

    XSetSelectionOwner(dpy, clipboard, win, CurrentTime);
    if (XGetSelectionOwner(dpy, clipboard) != win) {
        fprintf(stderr, "Failed to set clipboard owner.\n");
        XDestroyWindow(dpy, win);
        XCloseDisplay(dpy);
        exit(2);
    }

    XEvent evt;
    int running = 1;
    while (running) {
        XNextEvent(dpy, &evt);
        if (evt.type == SelectionRequest) {
            XSelectionRequestEvent *req = &evt.xselectionrequest;
            XEvent respond;
            memset(&respond, 0, sizeof(respond));
            respond.xselection.type = SelectionNotify;
            respond.xselection.display = req->display;
            respond.xselection.requestor = req->requestor;
            respond.xselection.selection = req->selection;
            respond.xselection.time = req->time;
            respond.xselection.target = req->target;
            respond.xselection.property = None;

            if (req->target == targets) {
                Atom types[2] = {utf8, XA_STRING};
                XChangeProperty(dpy, req->requestor, req->property, XA_ATOM, 32,
                                PropModeReplace, (unsigned char *)types, 2);
                respond.xselection.property = req->property;
            } else if (req->target == utf8 || req->target == XA_STRING) {
                XChangeProperty(dpy, req->requestor, req->property, req->target, 8,
                                PropModeReplace, (unsigned char *)str, strlen(str));
                respond.xselection.property = req->property;
            }
            XSendEvent(dpy, req->requestor, 0, 0, &respond);
            XFlush(dpy);
        } else if (evt.type == SelectionClear) {
            running = 0;
        }
    }

    XDestroyWindow(dpy, win);
    XCloseDisplay(dpy);
    exit(0);
}

int paste_from_clipboard(char * buffer) {
    Display *dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "No X11 display found.\n");
        return 1;
    }
    *buffer=0;

    Window win = XCreateSimpleWindow(dpy, DefaultRootWindow(dpy), 0, 0, 1, 1, 0, 0, 0);
    Atom clipboard = XInternAtom(dpy, "CLIPBOARD", False);
    Atom utf8 = XInternAtom(dpy, "UTF8_STRING", False);

    XConvertSelection(dpy, clipboard, utf8, clipboard, win, CurrentTime);

    XEvent evt;
    int done = 0;
    while (!done) {
        XNextEvent(dpy, &evt);
        if (evt.type == SelectionNotify && evt.xselection.selection == clipboard) {
            if (evt.xselection.property) {
                Atom actual_type;
                int actual_format;
                unsigned long nitems, bytes_after;
                unsigned char *prop;
                XGetWindowProperty(dpy, win, clipboard, 0, (~0L), False, utf8,
                                   &actual_type, &actual_format, &nitems, &bytes_after, &prop);
                if (prop) {
		    strncpy(buffer,prop,65536);
                    XFree(prop);
                }
            }
            done = 1;
        }
    }
    XDestroyWindow(dpy, win);
    XCloseDisplay(dpy);
    return 0;
}


