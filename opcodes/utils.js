const loop = (count, template) => {
    let res = [];
    for (var i = 0; i < count; i++) {
        res.push( template(i, count) );
    }
    return res.join('\n');
}

const $stop = 'debug;'