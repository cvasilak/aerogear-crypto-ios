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

#import <Foundation/Foundation.h>

extern const NSInteger AGPBKDF2Iterations;
extern const NSInteger AGPBKDF2MinimumIterations;
extern const NSInteger AGPBKDF2DerivedKeyLength;
extern const NSInteger AGPBKDF2MinimumSaltLength;

@interface AGPBKDF2 : NSObject

- (NSData *)deriveKey:(NSString *)password;
- (NSData *)deriveKey:(NSString *)password salt:(NSData *)salt;
- (NSData *)deriveKey:(NSString *)password salt:(NSData *)salt iterations:(NSInteger)iterations;
- (BOOL)validate:(NSString *)password encryptedPassword:(NSData *)encryptedPassword salt:(NSData *)salt;
- (NSData *)salt;

@end
