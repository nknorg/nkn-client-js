module.exports = function(grunt) {
  grunt.initConfig({
    browserify: {
      dist: {
        files: {
          'dist/nkn.js': [ 'lib/nkn.js' ]
        },
        options: {
          exclude: ['crypto'],
          browserifyOptions: {
            standalone: 'nkn'
          }
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
