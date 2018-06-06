/* global __dirname */

import path from 'path';
import HtmlWebpackPlugin from 'html-webpack-plugin';

export default {
  entry: './js/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    publicPath: 'dist/',
    filename: 'index_bundle.js'
  },
  plugins: [
    new HtmlWebpackPlugin({
      title: 'Conduit Dashboard',
      template: 'index.html',
    }),
  ],
  devtool: 'cheap-module-source-map',
  externals: {
    cheerio: 'window',
    'react/addons': 'react',
    'react/lib/ExecutionEnvironment': 'react',
    'react/lib/ReactContext': 'react',
    'react-addons-test-utils': 'react-dom',
  },
  module: {
    rules: [
      {
        test: /\.jsx?$/,
        exclude: /node_modules/,
        use: [
          'babel-loader',
          { loader: 'eslint-loader', options: { fix: true } }
        ]
      },
      {
        test: /\.css$/,
        use: [
          'style-loader',
          { loader: 'css-loader', options: { importLoaders: 1, minimize: true } },
          'postcss-loader'
        ]
      },
      {
        test: /\.(png|jpg|gif|eot|svg|ttf|woff|woff2)$/,
        use: [
          {
            loader: 'file-loader',
            options: { publicPath: 'dist/' }
          }
        ]
      }
    ]
  }
}
