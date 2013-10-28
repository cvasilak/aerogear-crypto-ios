/*
 * JBoss, Home of Professional Open Source.
 * Copyright Red Hat, Inc., and individual contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import "AGKeyPair.h"

#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

@implementation AGKeyPair

@synthesize pubKey = _pubKey;
@synthesize privKey = _privKey;

- (id)initWithKeySize:(NSUInteger)size {
    self = [super init];
    if (self) {
        
        CFDictionaryRef keyDefinitions;
        CFTypeRef keys[2];
        CFTypeRef values[2];
        
        // set up params for generation
        keys[0] = kSecAttrKeyType;
        values[0] = kSecAttrKeyTypeEC; // elliptic-curve
        
        keys[1] = kSecAttrKeySizeInBits;
        values[1] = CFNumberCreate(NULL, kCFNumberIntType, &size);
        
        keyDefinitions = CFDictionaryCreate(
                                            NULL, keys, values, sizeof(keys) / sizeof(keys[0]), NULL, NULL );
        
        // generate them
        OSStatus status = SecKeyGeneratePair(keyDefinitions,
                                             &_pubKey, &_privKey);
        
        // can't do much if there was an error in keygen
        if (status != errSecSuccess)
            return nil;
        
    }
    
    return self;
}

@end
