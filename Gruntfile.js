module.exports = function(grunt) {
  grunt.initConfig({
    browserify: {
      dist: {
        files: {
          'dist/nkn.js': [ 'lib/nkn.js' ]
        },
        options: {
          browserifyOptions: {
            standalone: 'nkn'
          },
          transform: [
            [
              "browserify-replace",
              {
                replace: [
                  { from: "var global = Function\\('return this'\\)\\(\\);", to: "var global = (function(){ return this }).call(null);" }
                ]
              }
            ]
          ]
        }
      }
    },
    uglify: {
      dist: {
        files: {
          'dist/nkn.min.js' : [ 'dist/nkn.js' ]
        }
      }
    }
  });

  grunt.loadNpmTasks('grunt-browserify');
  grunt.loadNpmTasks('grunt-contrib-uglify-es');

  grunt.registerTask('dist', ['browserify', 'uglify']);
};
