const loop = (count, template) => {
    let res = '';
    for (var i = 0; i < count; i++) {
        res += template(i, count) + "\n";
    }
    return res;
}

const $stop = 'debug;'