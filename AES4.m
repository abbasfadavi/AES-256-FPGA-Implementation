clc,clear
fs = 100e6;
ts = 1/fs;
%%
key = randi([0 255],1,32,'uint8');
data_i = randi([0 255],1,16,'uint8');
%%
data_d = AES_Encrypt(data_i', key)'
data_o = AES_Decrypt(data_d, key)';
sum(data_i == data_o)

[data_i;data_d;data_o]


%% ---------------- AES Encrypt Block ----------------
function out = AES_Encrypt(inBytes, key)
expandedKey = keyExpansion256(key);
    % inBytes: 16x1 uint8
    Nb = 4; 
    Nr = 14;
    state = reshape(inBytes,4,4); 

    % initial AddRoundKey (round 0)
    state = bitxor(state, expandedKey(:,1:Nb));

    for round = 1:Nr-1
        state = subBytes(state);
        state = shiftRows(state);
        state = mixColumns(state);
        state = bitxor(state, expandedKey(:, round*Nb+1:(round+1)*Nb));
    end

    % final round (no mixColumns)
     state = subBytes(state);
     state = shiftRows(state);
     state = bitxor(state, expandedKey(:, Nr*Nb+1:(Nr+1)*Nb));

    out = state(:)
end

%% ---------------- AES Decrypt Block ----------------
function out = AES_Decrypt(inBytes, key)
expandedKey = keyExpansion256(key);
    % inBytes: 16x1 uint8 (ciphertext block)
    Nb = 4; Nr = 14;
    state = reshape(inBytes,4,4);

    % initial AddRoundKey with last round key
    state = bitxor(state, expandedKey(:, Nr*Nb+1:(Nr+1)*Nb));

    for round = Nr-1:-1:1
        state = invShiftRows(state);
        state = invSubBytes(state);
        state = bitxor(state, expandedKey(:, round*Nb+1:(round+1)*Nb));
        state = invMixColumns(state);
    end

    % final round
    state = invShiftRows(state);
    state = invSubBytes(state);
    state = bitxor(state, expandedKey(:,1:Nb));

    out = state(:);
end
%%
function w = subWord(w)
    w = subBytes(w);
end
%%
function s = subBytes(state)
    sbox = aes_sbox();
    s = arrayfun(@(x) sbox(double(x)+1), state); % +1 for MATLAB indexing
    s = uint8(s);
end



function sbox = aes_sbox()
    persistent sb;
    if isempty(sb)
        sb = uint8([
        99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,...
        202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,...
        183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,...
        4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,...
        9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,...
        83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,...
        208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,...
        81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210,...
        205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115,...
        96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,...
        224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,...
        231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8,...
        186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,...
        112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,...
        225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,...
        140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22 ]);
        sb = reshape(sb,1,[]);
    end
    sbox = sb;
end

%% ---------------- ShiftRows ----------------
function st = shiftRows(st)
    st(2,:) = circshift(st(2,:), [0 -1]);
    st(3,:) = circshift(st(3,:), [0 -2]);
    st(4,:) = circshift(st(4,:), [0 -3]);
end

%% ---------------- MixColumns ----------------
function st = mixColumns(st)
    for c = 1:4
        a = double(st(:,c));
        st(1,c) = bitxor( bitxor( bitxor( gmul(a(1),2), gmul(a(2),3) ), a(3) ), a(4) );
        st(2,c) = bitxor( bitxor( bitxor( a(1), gmul(a(2),2) ), gmul(a(3),3) ), a(4) );
        st(3,c) = bitxor( bitxor( bitxor( a(1), a(2) ), gmul(a(3),2) ), gmul(a(4),3) );
        st(4,c) = bitxor( bitxor( bitxor( gmul(a(1),3), a(2) ), a(3) ), gmul(a(4),2) );
    end
    st = uint8(st);
end

%% ---------------- Galois Field multiplication ----------------
function r = gmul(a,b)
    a = uint16(a); b = uint16(b);
    p = uint16(0);
    for i = 1:8
        if bitand(b,1)
            p = bitxor(p, a);
        end
        carry = bitand(a, 128);
        a = bitshift(a,1);
        if carry
            a = bitxor(a, 27); % 0x1b
        end
        b = bitshift(b,-1);
    end
    r = uint8(bitand(p,255));
end

%% ---------------- rotWord ----------------
function w = rotWord(w)
    w = circshift(w,-1);
end

%% ---------------- Inverse operations ----------------
function st = invSubBytes(st)
    invs = aes_inv_sbox();
    st = arrayfun(@(x) invs(double(x)+1), st);
    st = uint8(st);
end

function inv = aes_inv_sbox()
    persistent invs;
    if isempty(invs)
        s = aes_sbox();
        invs = uint8(zeros(1,256));
        for i = 0:255
            invs(double(s(i+1))+1) = uint8(i);
        end
    end
    inv = invs;
end
%%
function st = invShiftRows(st)
    st(2,:) = circshift(st(2,:), [0 1]);
    st(3,:) = circshift(st(3,:), [0 2]);
    st(4,:) = circshift(st(4,:), [0 3]);
end
%5
function st = invMixColumns(st)
    for c = 1:4
        a = double(st(:,c));
        st(1,c) = bitxor( bitxor( bitxor( gmul(a(1),14), gmul(a(2),11) ), gmul(a(3),13) ), gmul(a(4),9) );
        st(2,c) = bitxor( bitxor( bitxor( gmul(a(1),9),  gmul(a(2),14) ), gmul(a(3),11) ), gmul(a(4),13) );
        st(3,c) = bitxor( bitxor( bitxor( gmul(a(1),13), gmul(a(2),9)  ), gmul(a(3),14) ), gmul(a(4),11) );
        st(4,c) = bitxor( bitxor( bitxor( gmul(a(1),11), gmul(a(2),13) ), gmul(a(3),9)  ), gmul(a(4),14) );
    end
    st = uint8(st);
end
%%
function expandedKey = keyExpansion256(key)
    % key: 32 bytes (uint8)
    Nk = 8;
    Nr = 14;
    Nb = 4;
    totalWords = Nb*(Nr+1);
    expandedKey = zeros(4, totalWords, 'uint8');
    for i = 1:Nk
        expandedKey(:,i) = key(4*(i-1)+1:4*i);
    end

    % Rcon words
    numRcon = ceil(totalWords / Nk);
    Rcon = uint8(zeros(4, numRcon));
    Rcon(:,1) = uint8([1;0;0;0]);
    for j = 2:numRcon
        prev = double(Rcon(1,j-1));
        val = mod(prev*2,256);
        if prev >= 128
            val = bitxor(val, 27); % 0x1b
        end
        Rcon(:,j) = uint8([val;0;0;0]);
    end

    for i = Nk+1:totalWords
        temp = expandedKey(:,i-1);
        if mod(i-1, Nk) == 0
            temp = bitxor(subWord(rotWord(temp)), Rcon(:, (i-1)/Nk ));
        elseif mod(i-1, Nk) == 4
            temp = subWord(temp);
        end
        expandedKey(:,i) = bitxor(expandedKey(:, i-Nk), temp);
    end
end
