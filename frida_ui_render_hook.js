// Frida UI Rendering Hook - Intercept text as it's rendered to screen
console.log('[*] ChatGPT UI Rendering Interceptor Starting...');

const logFile = '/tmp/ui_render_intercept.txt';
let capturedText = [];

// ===== Hook UILabel and UITextView (UIKit) =====
console.log('[1/5] Hooking UIKit text rendering...');

try {
    // UILabel setText
    if (ObjC.classes.UILabel) {
        const UILabel = ObjC.classes.UILabel;
        const setText = UILabel['- setText:'];

        if (setText) {
            Interceptor.attach(setText.implementation, {
                onEnter: function(args) {
                    try {
                        const text = new ObjC.Object(args[2]).toString();
                        if (text && text.length > 50 && text.length < 10000) {
                            console.log('\n[UILabel]', text.substring(0, 300));
                            capturedText.push({type: 'UILabel', text: text});
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] Hooked UILabel.setText');
        }
    }

    // UITextView setText
    if (ObjC.classes.UITextView) {
        const UITextView = ObjC.classes.UITextView;
        const setText = UITextView['- setText:'];

        if (setText) {
            Interceptor.attach(setText.implementation, {
                onEnter: function(args) {
                    try {
                        const text = new ObjC.Object(args[2]).toString();
                        if (text && text.length > 50 && text.length < 10000) {
                            console.log('\n[UITextView]', text.substring(0, 300));
                            capturedText.push({type: 'UITextView', text: text});
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] Hooked UITextView.setText');
        }
    }
} catch (e) {
    console.log('[-] UIKit hooking error:', e.message);
}

// ===== Hook WKWebView JavaScript evaluation =====
console.log('\n[2/5] Hooking WKWebView...');

try {
    if (ObjC.classes.WKWebView) {
        const WKWebView = ObjC.classes.WKWebView;

        // Hook evaluateJavaScript
        const evalJS = WKWebView['- evaluateJavaScript:completionHandler:'];
        if (evalJS) {
            Interceptor.attach(evalJS.implementation, {
                onEnter: function(args) {
                    try {
                        const js = new ObjC.Object(args[2]).toString();
                        if (js && js.length > 10) {
                            console.log('\n[WKWebView JS]', js.substring(0, 200));
                        }
                    } catch (e) {}
                }
            });
            console.log('[+] Hooked WKWebView.evaluateJavaScript');
        }
    }
} catch (e) {
    console.log('[-] WKWebView hooking error:', e.message);
}

// ===== Hook NSAttributedString (used for rich text) =====
console.log('\n[3/5] Hooking NSAttributedString...');

try {
    const NSAttributedString = ObjC.classes.NSAttributedString;
    const initWithString = NSAttributedString['- initWithString:'];

    if (initWithString) {
        Interceptor.attach(initWithString.implementation, {
            onEnter: function(args) {
                try {
                    const text = new ObjC.Object(args[2]).toString();
                    if (text && text.length > 50 && text.length < 10000) {
                        // Filter out system strings
                        if (!text.includes('http://') &&
                            !text.includes('file://') &&
                            !text.includes('CFBundle')) {
                            console.log('\n[NSAttributedString]', text.substring(0, 300));
                            capturedText.push({type: 'NSAttributedString', text: text});
                        }
                    }
                } catch (e) {}
            }
        });
        console.log('[+] Hooked NSAttributedString.initWithString');
    }
} catch (e) {
    console.log('[-] NSAttributedString hooking error:', e.message);
}

// ===== Hook Core Graphics text drawing =====
console.log('\n[4/5] Hooking Core Graphics text drawing...');

try {
    // CGContextShowText
    const CGContextShowText = Module.findExportByName('CoreGraphics', 'CGContextShowText');
    if (CGContextShowText) {
        Interceptor.attach(CGContextShowText, {
            onEnter: function(args) {
                try {
                    const textPtr = args[1];
                    const text = Memory.readUtf8String(textPtr);
                    if (text && text.length > 20 && text.length < 5000) {
                        console.log('\n[CGContextShowText]', text.substring(0, 200));
                    }
                } catch (e) {}
            }
        });
        console.log('[+] Hooked CGContextShowText');
    }

    // CGContextShowTextAtPoint
    const CGContextShowTextAtPoint = Module.findExportByName('CoreGraphics', 'CGContextShowTextAtPoint');
    if (CGContextShowTextAtPoint) {
        Interceptor.attach(CGContextShowTextAtPoint, {
            onEnter: function(args) {
                try {
                    const textPtr = args[3];
                    const text = Memory.readUtf8String(textPtr);
                    if (text && text.length > 20 && text.length < 5000) {
                        console.log('\n[CGContextShowTextAtPoint]', text.substring(0, 200));
                    }
                } catch (e) {}
            }
        });
        console.log('[+] Hooked CGContextShowTextAtPoint');
    }
} catch (e) {
    console.log('[-] Core Graphics hooking error:', e.message);
}

// ===== Hook SwiftUI Text rendering (Swift runtime) =====
console.log('\n[5/5] Searching for SwiftUI Text classes...');

try {
    let swiftTextClasses = [];

    for (const className of Object.keys(ObjC.classes)) {
        const lowerName = className.toLowerCase();
        if (lowerName.includes('text') &&
            (lowerName.includes('view') ||
             lowerName.includes('cell') ||
             lowerName.includes('label') ||
             lowerName.includes('message') ||
             lowerName.includes('conversation'))) {
            swiftTextClasses.push(className);
        }
    }

    console.log(`[+] Found ${swiftTextClasses.length} potential text classes`);
    swiftTextClasses.slice(0, 30).forEach(name => console.log('    -', name));

    // Try to hook init methods of these classes
    for (const className of swiftTextClasses.slice(0, 20)) {
        try {
            const cls = ObjC.classes[className];
            const methods = cls.$ownMethods;

            for (const method of methods) {
                const methodName = method.toLowerCase();
                if (methodName.includes('init') ||
                    methodName.includes('settext') ||
                    methodName.includes('setcontent')) {

                    try {
                        const impl = cls[method];
                        if (impl && impl.implementation) {
                            Interceptor.attach(impl.implementation, {
                                onEnter: function(args) {
                                    // Try to extract any string arguments
                                    for (let i = 2; i < Math.min(args.length, 8); i++) {
                                        try {
                                            const obj = new ObjC.Object(args[i]);
                                            const str = obj.toString();
                                            if (str && str.length > 50 && str.length < 10000) {
                                                console.log(`\n[${className}.${method}]`, str.substring(0, 300));
                                                capturedText.push({type: className, method: method, text: str});
                                            }
                                        } catch (e) {}
                                    }
                                }
                            });
                        }
                    } catch (e) {}
                }
            }
        } catch (e) {}
    }
} catch (e) {
    console.log('[-] SwiftUI hooking error:', e.message);
}

// ===== Save captured text periodically =====
setInterval(() => {
    if (capturedText.length > 0) {
        try {
            const file = new File(logFile, 'a');
            file.write(`\n\n=== Capture at ${new Date().toISOString()} ===\n`);

            capturedText.forEach((item, idx) => {
                file.write(`\n[${idx + 1}] Type: ${item.type}\n`);
                if (item.method) file.write(`Method: ${item.method}\n`);
                file.write(`Text: ${item.text}\n`);
                file.write('-'.repeat(80) + '\n');
            });

            file.close();
            console.log(`\n[+] Saved ${capturedText.length} text captures to ${logFile}`);
            capturedText = [];
        } catch (e) {
            console.log('[-] Save error:', e.message);
        }
    }
}, 10000);

console.log('\n' + '='.repeat(80));
console.log('[*] UI rendering hooks active!');
console.log('[*] Send a ChatGPT message and watch for text interceptions');
console.log('[*] Captured text will be logged to:', logFile);
console.log('[*] This intercepts text at the UI layer (last chance!)');
console.log('='.repeat(80) + '\n');
