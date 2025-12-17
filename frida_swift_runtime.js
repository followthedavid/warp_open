// Frida Swift Runtime Introspection
console.log('[*] Swift Runtime Explorer Starting...');

const logFile = '/tmp/swift_runtime_types.txt';

// ===== Find Swift Runtime Functions =====
console.log('[1/4] Locating Swift runtime functions...');

const swift_getTypeByMangledNameInContext = Module.findExportByName(null, 'swift_getTypeByMangledNameInContext');
const swift_getTypeByMangledNameInEnvironment = Module.findExportByName(null, 'swift_getTypeByMangledNameInEnvironment');
const swift_getTypeByName = Module.findExportByName(null, 'swift_getTypeByName');
const swift_getTypeName = Module.findExportByName(null, 'swift_getTypeName');
const swift_demangle = Module.findExportByName(null, 'swift_demangle');

console.log('Swift runtime functions:');
console.log('  getTypeByMangledNameInContext:', swift_getTypeByMangledNameInContext);
console.log('  getTypeByMangledNameInEnvironment:', swift_getTypeByMangledNameInEnvironment);
console.log('  getTypeByName:', swift_getTypeByName);
console.log('  getTypeName:', swift_getTypeName);
console.log('  swift_demangle:', swift_demangle);

// ===== Enumerate All Images =====
console.log('\n[2/4] Enumerating loaded images...');

const images = Process.enumerateModules();
const chatgptImages = images.filter(m =>
    m.name.toLowerCase().includes('chatgpt') ||
    m.path.includes('ChatGPT.app')
);

console.log(`[+] Found ${chatgptImages.length} ChatGPT-related images:`);
chatgptImages.forEach(img => {
    console.log(`    - ${img.name} at ${img.base}`);
});

// ===== Search for Swift Type Metadata =====
console.log('\n[3/4] Searching for Swift type metadata...');

// Swift metadata typically starts with specific patterns
// We'll search memory for these patterns
try {
    let foundTypes = [];

    for (const image of chatgptImages) {
        console.log(`\n[*] Scanning ${image.name}...`);

        // Search for common Swift class/struct patterns in __TEXT segment
        const patterns = [
            'ConversationView',
            'MessageView',
            'ChatView',
            'ResponseModel',
            'MessageModel',
            'ConversationModel'
        ];

        for (const pattern of patterns) {
            try {
                const matches = Memory.scanSync(image.base, image.size, pattern);
                if (matches.length > 0) {
                    console.log(`  [FOUND] "${pattern}" at ${matches.length} locations`);
                    foundTypes.push({
                        pattern: pattern,
                        locations: matches.map(m => m.address.toString())
                    });
                }
            } catch (e) {
                // Continue on errors
            }
        }
    }

    if (foundTypes.length > 0) {
        console.log(`\n[+] Found ${foundTypes.length} potential type names!`);

        const file = new File(logFile, 'w');
        file.write('=== Swift Type Discovery ===\n\n');
        foundTypes.forEach(type => {
            file.write(`Type: ${type.pattern}\n`);
            file.write(`Locations: ${type.locations.join(', ')}\n\n`);
        });
        file.close();
    }
} catch (e) {
    console.log('[-] Type scanning error:', e.message);
}

// ===== Hook Swift String Initialization =====
console.log('\n[4/4] Hooking Swift String operations...');

try {
    // Swift String initializers
    const swiftStringInit = Module.findExportByName(null, 'swift_stringFromUTF8');
    if (swiftStringInit) {
        console.log('[+] Found swift_stringFromUTF8');

        Interceptor.attach(swiftStringInit, {
            onEnter: function(args) {
                try {
                    const strPtr = args[0];
                    const length = args[1].toInt32();

                    if (length > 50 && length < 10000) {
                        const str = Memory.readUtf8String(strPtr, length);

                        // Filter out system strings
                        if (str && !str.includes('http://') &&
                            !str.includes('file://') &&
                            !str.includes('NSBundle')) {

                            console.log('\n[Swift String]', length, 'chars:', str.substring(0, 300));

                            const file = new File(logFile, 'a');
                            file.write(`\n=== Swift String (${new Date().toISOString()}) ===\n`);
                            file.write(`Length: ${length}\n`);
                            file.write(`Content: ${str}\n`);
                            file.write('-'.repeat(80) + '\n');
                            file.close();
                        }
                    }
                } catch (e) {}
            }
        });
    }

    // Also hook _swift_stdlib_reportUnimplementedInitializer
    const swiftAlloc = Module.findExportByName(null, 'swift_allocObject');
    if (swiftAlloc) {
        console.log('[+] Found swift_allocObject');

        let allocCount = 0;
        Interceptor.attach(swiftAlloc, {
            onEnter: function(args) {
                allocCount++;
                if (allocCount % 100 === 0) {
                    console.log(`[*] Swift objects allocated: ${allocCount}`);
                }
            }
        });
    }

} catch (e) {
    console.log('[-] Swift hook error:', e.message);
}

// ===== Try to enumerate ObjC classes that wrap Swift =====
console.log('\n[*] Looking for ObjC-wrapped Swift classes...');

try {
    let swiftWrappedClasses = [];

    for (const className of Object.keys(ObjC.classes)) {
        // Swift classes often have module prefixes
        if (className.includes('ChatGPT') ||
            className.includes('Conversation') ||
            className.includes('Message')) {

            swiftWrappedClasses.push(className);
            console.log(`  [+] Found: ${className}`);

            try {
                const cls = ObjC.classes[className];
                const methods = cls.$ownMethods;

                console.log(`      Methods (${methods.length}):`);
                methods.slice(0, 10).forEach(m => {
                    console.log(`        - ${m}`);
                });

                // Try to hook interesting methods
                for (const method of methods) {
                    const methodLower = method.toLowerCase();
                    if (methodLower.includes('text') ||
                        methodLower.includes('content') ||
                        methodLower.includes('message')) {

                        try {
                            const impl = cls[method];
                            if (impl && impl.implementation) {
                                Interceptor.attach(impl.implementation, {
                                    onEnter: function(args) {
                                        console.log(`\n[${className}.${method}] called`);

                                        // Try to log arguments
                                        for (let i = 2; i < Math.min(args.length, 5); i++) {
                                            try {
                                                const obj = new ObjC.Object(args[i]);
                                                const str = obj.toString();
                                                if (str && str.length > 20 && str.length < 5000) {
                                                    console.log(`  arg[${i}]:`, str.substring(0, 200));
                                                }
                                            } catch (e) {}
                                        }
                                    },
                                    onLeave: function(retval) {
                                        try {
                                            const obj = new ObjC.Object(retval);
                                            const str = obj.toString();
                                            if (str && str.length > 20) {
                                                console.log('  return:', str.substring(0, 200));
                                            }
                                        } catch (e) {}
                                    }
                                });
                                console.log(`      [+] Hooked ${className}.${method}`);
                            }
                        } catch (e) {}
                    }
                }
            } catch (e) {
                console.log(`      [-] Error inspecting ${className}:`, e.message);
            }
        }
    }

    console.log(`\n[+] Found ${swiftWrappedClasses.length} Swift-related classes`);

} catch (e) {
    console.log('[-] ObjC enumeration error:', e.message);
}

console.log('\n' + '='.repeat(80));
console.log('[*] Swift runtime hooks active!');
console.log('[*] Send a ChatGPT message and watch for interceptions');
console.log('[*] Results logged to:', logFile);
console.log('='.repeat(80) + '\n');
